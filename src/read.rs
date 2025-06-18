use alloy::network::{AnyNetwork, TransactionBuilder};
use alloy::primitives::{Address, U64};
use alloy::providers::fillers::FillProvider;
use alloy::providers::mock::Asserter;
use alloy::providers::utils::JoinedRecommendedFillers;
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::TransactionRequest;
use alloy::serde::WithOtherFields;
use alloy::sol_types::SolCall;
use alloy::transports::{RpcError, TransportErrorKind};
use derive_builder::Builder;
use std::collections::HashMap;
use thiserror::Error;
use url::Url;

use rain_error_decoding::{AbiDecodeFailedErrors, AbiDecodedErrorType};

#[derive(Error, Debug)]
pub enum ReadableClientError {
    #[error("failed to instantiate provider: {0}")]
    CreateReadableClientHttpError(String),
    #[error(transparent)]
    RpcTransportKindError(#[from] RpcError<TransportErrorKind>),
    #[error("failed to decode return: {0}")]
    ReadDecodeReturnError(String),
    #[error("failed to get chain id: {0}")]
    ReadChainIdError(String),
    #[error("failed to get block number: {0}")]
    ReadBlockNumberError(String),
    #[error(transparent)]
    AbiDecodeFailedErrors(#[from] AbiDecodeFailedErrors),
    #[error(transparent)]
    AbiDecodedErrorType(#[from] AbiDecodedErrorType),
    #[error("all providers failed to handle the request: {0:?}")]
    AllProvidersFailed(HashMap<String, ReadableClientError>),
    #[error("rpc provider '{0}' returned an error: '{1}'")]
    RpcProviderError(String, String),
}

#[derive(Builder)]
pub struct ReadContractParameters<C: SolCall> {
    pub address: Address,
    pub call: C,
    #[builder(setter(into), default)]
    pub block_number: Option<U64>,
    #[builder(setter(into), default)]
    pub gas: Option<u64>,
}

pub type ReadProvider =
    FillProvider<JoinedRecommendedFillers, RootProvider<AnyNetwork>, AnyNetwork>;

#[derive(Debug, Clone)]
pub struct ReadableClient {
    providers: HashMap<String, ReadProvider>,
}

const MOCKED_PROVIDER_KEY: &str = "mocked_url";

impl ReadableClient {
    pub async fn new_from_url(url: String) -> Result<Self, ReadableClientError> {
        let provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect(&url)
            .await?;

        Ok(Self {
            providers: HashMap::from([(url, provider)]),
        })
    }

    pub fn new_from_http_urls(urls: Vec<String>) -> Result<Self, ReadableClientError> {
        let providers: HashMap<String, _> = urls
            .iter()
            .filter_map(|url| {
                let rpc_url: Url = url.parse().ok()?;
                if !rpc_url.scheme().starts_with("http") {
                    return None;
                }

                Some((
                    url.to_owned(),
                    ProviderBuilder::new()
                        .network::<AnyNetwork>()
                        .connect_http(rpc_url),
                ))
            })
            .collect();

        if providers.is_empty() {
            Err(ReadableClientError::CreateReadableClientHttpError(format!(
                "No valid providers could be created from the given URLs: {urls:?}"
            )))
        } else {
            Ok(Self { providers })
        }
    }

    pub fn new_mocked(asserter: Asserter) -> Self {
        let provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter);
        Self {
            providers: HashMap::from([(MOCKED_PROVIDER_KEY.to_string(), provider)]),
        }
    }

    pub fn new(providers: HashMap<String, ReadProvider>) -> Result<Self, ReadableClientError> {
        if providers.is_empty() {
            Err(ReadableClientError::CreateReadableClientHttpError(
                "cannot initiate a read client with no providers given".to_string(),
            ))
        } else {
            Ok(Self { providers })
        }
    }

    /// Attempts to execute the provided asynchronous operation with each
    /// configured provider until one succeeds.
    ///
    /// # Arguments
    ///
    /// * `operation` - A closure that takes a reference to a [`ReadProvider`]
    ///   and returns a future resolving to a `Result<T, ReadableClientError>`.
    ///
    /// # Type Parameters
    ///
    /// * `T` - The type of the successful result returned by the operation.
    /// * `Fut` - The future returned by the operation closure.
    /// * `F` - The closure type, which must accept a `&ReadProvider` and
    ///   return a `Fut`.
    ///
    /// # Returns
    ///
    /// * `Ok(T)` if the operation succeeds with any provider.
    /// * `Err(ReadableClientError::AllProvidersFailed)` if all providers fail,
    ///   containing a map of provider URLs to their respective errors.
    ///
    /// # Errors
    ///
    /// Returns `ReadableClientError::AllProvidersFailed` if the operation fails
    /// for all providers.
    async fn on_providers<'a, T, Fut, F>(
        &'a self,
        mut operation: F,
    ) -> Result<T, ReadableClientError>
    where
        F: FnMut(&'a ReadProvider) -> Fut,
        Fut: std::future::Future<Output = Result<T, ReadableClientError>> + 'a,
    {
        let mut errors: HashMap<String, ReadableClientError> = HashMap::new();

        for (url, provider) in &self.providers {
            match operation(provider).await {
                Ok(value) => return Ok(value),
                Err(err) => {
                    errors.insert(url.clone(), err);
                }
            }
        }

        Err(ReadableClientError::AllProvidersFailed(errors))
    }

    // Executes a read function on a contract.
    pub async fn read<C: SolCall>(
        &self,
        parameters: ReadContractParameters<C>,
    ) -> Result<<C as SolCall>::Return, ReadableClientError> {
        let data = parameters.call.abi_encode();

        let transaction_request = TransactionRequest::default()
            .with_to(parameters.address)
            .with_input(data);

        let transaction_request = if let Some(gas) = parameters.gas {
            transaction_request.with_gas_limit(gas) // NOTE: check that this is the right param
        } else {
            transaction_request
        };

        self.on_providers(|provider| {
            let transaction_request = transaction_request.clone();
            async move {
                match provider
                    .call(WithOtherFields::new(transaction_request))
                    .await
                {
                    Ok(res) => C::abi_decode_returns(res.to_vec().as_slice())
                        .map_err(|err| ReadableClientError::ReadDecodeReturnError(err.to_string())),
                    Err(provider_err) => {
                        if let Some(rpc_err) = provider_err.as_error_resp() {
                            match AbiDecodedErrorType::try_from_json_rpc_error(rpc_err.clone())
                                .await
                            {
                                Ok(decoded_err) => {
                                    Err(ReadableClientError::AbiDecodedErrorType(decoded_err))
                                }
                                Err(decode_failed_err) => Err(
                                    ReadableClientError::AbiDecodeFailedErrors(decode_failed_err),
                                ),
                            }
                        } else {
                            Err(ReadableClientError::RpcTransportKindError(provider_err))
                        }
                    }
                }
            }
        })
        .await
    }

    pub async fn get_chainid(&self) -> Result<u64, ReadableClientError> {
        self.on_providers(|provider| async move {
            provider
                .get_chain_id()
                .await
                .map_err(|err| ReadableClientError::ReadChainIdError(err.to_string()))
        })
        .await
    }

    pub async fn get_block_number(&self) -> Result<u64, ReadableClientError> {
        self.on_providers(|provider| async move {
            provider
                .get_block_number()
                .await
                .map_err(|err| ReadableClientError::ReadBlockNumberError(err.to_string()))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256};
    use alloy::rpc::json_rpc::ErrorPayload;
    use alloy::sol;
    use serde_json::json;
    use serde_json::value::RawValue;

    sol! {
       function foo(uint256 a, uint256 b) external view returns (Foo);

        struct Foo {
            uint256 bar;
            address baz;
        }
    }

    #[tokio::test]
    async fn test_builder() -> anyhow::Result<()> {
        // block_number is optional so this should work
        let parameters = ReadContractParametersBuilder::default()
            .address(Address::repeat_byte(0x11))
            .call(fooCall {
                a: U256::from(42),
                b: U256::from(10),
            })
            .build()?;

        assert_eq!(parameters.address, Address::repeat_byte(0x11));
        assert_eq!(parameters.call.a, U256::from(42));
        assert_eq!(parameters.call.b, U256::from(10));

        // but we can also set block number without needing Some(block_number)
        let parameters = ReadContractParametersBuilder::default()
            .address(Address::repeat_byte(0x11))
            .call(fooCall {
                a: U256::from(42),
                b: U256::from(10),
            })
            .block_number(Some(U64::from(1)))
            .build()?;

        assert_eq!(parameters.address, Address::repeat_byte(0x11));
        assert_eq!(parameters.call.a, U256::from(42));
        assert_eq!(parameters.call.b, U256::from(10));

        Ok(())
    }

    #[tokio::test]
    async fn test_read_return() -> anyhow::Result<()> {
        let asserter = Asserter::new();

        asserter.push_success(&json!("0x000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000001111111111111111111111111111111111111111"));

        // Create a ReadableClient instance with the mock provider
        let read_contract = ReadableClient::new_mocked(asserter);

        // Create a ReadContractParameters instance
        let parameters = ReadContractParametersBuilder::default()
            .call(fooCall {
                a: U256::from(42), // these could be anything, the mock provider doesn't care
                b: U256::from(10),
            })
            .address(Address::repeat_byte(0x22))
            .build()?;

        // Call the read method
        let result = read_contract.read(parameters).await?;

        let bar = result.bar;
        let baz = result.baz;

        assert_eq!(bar, U256::from(42));
        assert_eq!(baz, Address::repeat_byte(0x11));

        Ok(())
    }

    #[tokio::test]
    async fn test_get_chainid() -> anyhow::Result<()> {
        let asserter = Asserter::new();

        asserter.push_success(&5_u64);

        let read_contract = ReadableClient::new_mocked(asserter);
        let res = read_contract.get_chainid().await.unwrap();

        assert_eq!(res, 5_u64);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_block_number() -> anyhow::Result<()> {
        let asserter = Asserter::new();
        asserter.push_success(&6_u64);

        let read_contract = ReadableClient::new_mocked(asserter);
        let res = read_contract.get_block_number().await.unwrap();

        assert_eq!(res, 6_u64);

        Ok(())
    }

    #[tokio::test]
    async fn test_decodable_error() -> anyhow::Result<()> {
        let asserter = Asserter::new();

        let mock_error = ErrorPayload {
            code: 3,
            data: Some(RawValue::from_string(r#""0x1ac66908""#.to_string()).unwrap()),
            message: "execution reverted".into(),
        };
        asserter.push_failure(mock_error);

        let read_contract = ReadableClient::new_mocked(asserter);

        // Create a ReadContractParameters instance
        let parameters = ReadContractParametersBuilder::default()
            .call(fooCall {
                a: U256::from(42), // these could be anything, the mock provider doesn't care
                b: U256::from(10),
            })
            .address(Address::repeat_byte(0x22))
            .build()?;

        // Call the read method
        let result = read_contract.read(parameters).await;

        assert!(result.is_err());

        let err = result.err().unwrap();

        match err {
            ReadableClientError::AllProvidersFailed(errors) => {
                assert_eq!(errors.len(), 1);

                assert!(errors.contains_key(MOCKED_PROVIDER_KEY));
                match errors.get(MOCKED_PROVIDER_KEY) {
                    Some(ReadableClientError::AbiDecodedErrorType(
                        AbiDecodedErrorType::Known {
                            name,
                            args,
                            sig,
                            data,
                        },
                    )) => {
                        assert_eq!(name, "UnexpectedOperandValue");
                        assert_eq!(args, &(vec![] as Vec<String>));
                        assert_eq!(sig, "UnexpectedOperandValue()");
                        assert_eq!(data, &vec![26, 198, 105, 8]);
                    }
                    _ => panic!("unexpected error type"),
                }
            }
            _ => panic!("unexpected error type"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_providers_read() -> anyhow::Result<()> {
        let asserter1 = Asserter::new();
        let asserter2 = Asserter::new();
        let asserter3 = Asserter::new();

        let mock_provider1 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter1.clone());
        let mock_provider2 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter2.clone());
        let mock_provider3 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter3.clone());

        let mock_response = "0x000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000001111111111111111111111111111111111111111";
        let mock_error = ErrorPayload {
            code: 3,
            data: None,
            message: "execution reverted".into(),
        };

        asserter1.push_failure(mock_error.clone());
        asserter2.push_failure(mock_error);
        asserter3.push_success(&mock_response);

        let read_contract = ReadableClient::new(HashMap::from([
            ("url1".to_string(), mock_provider1),
            ("url2".to_string(), mock_provider2),
            ("url3".to_string(), mock_provider3),
        ]))
        .unwrap();

        let parameters = ReadContractParametersBuilder::default()
            .call(fooCall {
                a: U256::from(42), // these could be anything, the mock provider doesn't care
                b: U256::from(10),
            })
            .address(Address::repeat_byte(0x22))
            .build()?;
        let result = read_contract.read(parameters).await?;

        let bar = result.bar;
        let baz = result.baz;
        assert_eq!(bar, U256::from(42));
        assert_eq!(baz, Address::repeat_byte(0x11));

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_providers_read_error() -> anyhow::Result<()> {
        let asserter1 = Asserter::new();
        let asserter2 = Asserter::new();
        let asserter3 = Asserter::new();
        let asserter4 = Asserter::new();

        let mock_provider1 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter1.clone());
        let mock_provider2 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter2.clone());
        let mock_provider3 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter3.clone());
        let mock_provider4 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter4.clone());

        asserter1.push_failure(ErrorPayload {
            code: 3,
            data: None,
            message: "execution reverted".into(),
        });
        asserter2.push_failure(ErrorPayload {
            code: 3,
            data: Some(RawValue::from_string(r#""0x1ac66908""#.to_string()).unwrap()),
            message: "some revert error".into(),
        });
        asserter3.push_failure(ErrorPayload {
            code: 3,
            data: Some(
                RawValue::from_string(json!({"error": "some other error"}).to_string()).unwrap(),
            ),
            message: "some other error".into(),
        });
        asserter4.push_failure(ErrorPayload {
            code: 3,
            data: Some(RawValue::from_string(json!(&vec![1]).to_string()).unwrap()),
            message: "some other error".into(),
        });

        let read_contract = ReadableClient::new(HashMap::from([
            ("url1".to_string(), mock_provider1),
            ("url2".to_string(), mock_provider2),
            ("url3".to_string(), mock_provider3),
            ("url4".to_string(), mock_provider4),
        ]))
        .unwrap();

        let parameters = ReadContractParametersBuilder::default()
            .call(fooCall {
                a: U256::from(42), // these could be anything, the mock provider doesn't care
                b: U256::from(10),
            })
            .address(Address::repeat_byte(0x22))
            .build()?;

        let res = read_contract.read(parameters).await;
        let err = res.err().unwrap();
        match err {
            ReadableClientError::AllProvidersFailed(errors) => {
                assert_eq!(errors.len(), 4);

                assert!(errors.contains_key("url1"));
                assert!(
                    matches!(
                        errors.get("url1"),
                        Some(ReadableClientError::AbiDecodeFailedErrors(
                            AbiDecodeFailedErrors::InvalidJsonRpcResponse(msg)
                        )) if msg.contains("execution reverted")
                    ),
                    "url1 error message should contain 'execution reverted' but got: {:?}",
                    errors.get("url1")
                );

                assert!(errors.contains_key("url2"));
                match errors.get("url2") {
                    Some(ReadableClientError::AbiDecodedErrorType(
                        AbiDecodedErrorType::Known {
                            name,
                            args,
                            sig,
                            data,
                        },
                    )) => {
                        assert_eq!(name, "UnexpectedOperandValue");
                        assert_eq!(args, &(vec![] as Vec<String>));
                        assert_eq!(sig, "UnexpectedOperandValue()");
                        assert_eq!(data, &vec![26, 198, 105, 8]);
                    }
                    _ => panic!("unexpected error type"),
                }

                assert!(errors.contains_key("url3"));
                assert!(matches!(
                    errors.get("url3"),
                    Some(ReadableClientError::AbiDecodeFailedErrors(
                        AbiDecodeFailedErrors::InvalidJsonRpcResponse(msg)
                    )) if msg.contains("some other error")
                ));

                assert!(errors.contains_key("url4"));
                assert!(matches!(
                    errors.get("url4"),
                    Some(ReadableClientError::AbiDecodeFailedErrors(
                        AbiDecodeFailedErrors::InvalidJsonRpcResponse(msg)
                    )) if msg.contains("some other error") && msg.contains("[1]")
                ));
            }
            _ => panic!("unexpected error type"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_providers_get_block_number() -> anyhow::Result<()> {
        let asserter1 = Asserter::new();
        let asserter2 = Asserter::new();
        let asserter3 = Asserter::new();

        let mock_provider1 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter1.clone());
        let mock_provider2 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter2.clone());
        let mock_provider3 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter3.clone());

        let mock_response = "0x0000006";
        let mock_error = ErrorPayload {
            code: 3,
            data: None,
            message: "execution reverted".into(),
        };

        asserter1.push_failure(mock_error.clone());
        asserter2.push_failure(mock_error.clone());
        asserter3.push_success(&mock_response);

        let read_contract = ReadableClient::new(HashMap::from([
            ("url1".to_string(), mock_provider1),
            ("url2".to_string(), mock_provider2),
            ("url3".to_string(), mock_provider3),
        ]))
        .unwrap();

        let res = read_contract.get_block_number().await.unwrap();
        assert_eq!(res, 6_u64);

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_providers_get_block_number_error() -> anyhow::Result<()> {
        let asserter = Asserter::new();

        let mock_provider1 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());
        let mock_provider2 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());

        let mock_error = ErrorPayload {
            code: 3,
            data: None,
            message: "execution reverted".into(),
        };
        asserter.push_failure(mock_error.clone());
        asserter.push_failure(mock_error);

        let read_contract = ReadableClient::new(HashMap::from([
            ("url1".to_string(), mock_provider1),
            ("url2".to_string(), mock_provider2),
        ]))
        .unwrap();

        let res = read_contract.get_block_number().await;
        let err = res.err().unwrap();
        match err {
            ReadableClientError::AllProvidersFailed(errors) => {
                assert_eq!(errors.len(), 2);

                assert!(errors.contains_key("url1"));
                assert!(matches!(
                    errors.get("url1"),
                    Some(ReadableClientError::ReadBlockNumberError(msg)) if msg.contains("execution reverted")
                ));

                assert!(errors.contains_key("url2"));
                assert!(matches!(
                    errors.get("url2"),
                    Some(ReadableClientError::ReadBlockNumberError(msg)) if msg.contains("execution reverted")
                ));
            }
            _ => panic!("unexpected error type"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_providers_get_chainid() -> anyhow::Result<()> {
        let asserter = Asserter::new();

        let mock_provider1 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());
        let mock_provider2 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());
        let mock_provider3 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());

        let mock_response = "0x00000005";
        let mock_error = ErrorPayload {
            code: 3,
            data: None,
            message: "execution reverted".into(),
        };

        asserter.push_failure(mock_error.clone());
        asserter.push_failure(mock_error.clone());
        asserter.push_success(&mock_response);

        let read_contract = ReadableClient::new(HashMap::from([
            ("url1".to_string(), mock_provider1),
            ("url2".to_string(), mock_provider2),
            ("url3".to_string(), mock_provider3),
        ]))
        .unwrap();

        let res = read_contract.get_chainid().await.unwrap();
        assert_eq!(res, 5_u64);

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_providers_get_chainid_error() -> anyhow::Result<()> {
        let asserter = Asserter::new();

        let mock_provider1 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());
        let mock_provider2 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());

        let err = ErrorPayload {
            code: 3,
            message: "execution reverted".into(),
            data: None,
        };
        asserter.push_failure(err.clone());
        asserter.push_failure(err);

        let read_contract = ReadableClient::new(HashMap::from([
            ("url1".to_string(), mock_provider1),
            ("url2".to_string(), mock_provider2),
        ]))
        .unwrap();

        let res = read_contract.get_chainid().await;
        let err = res.err().unwrap();
        match err {
            ReadableClientError::AllProvidersFailed(errors) => {
                assert_eq!(errors.len(), 2);

                assert!(errors.contains_key("url1"));
                assert!(matches!(
                    errors.get("url1"),
                    Some(ReadableClientError::ReadChainIdError(msg)) if msg.contains("execution reverted")
                ));

                assert!(errors.contains_key("url2"));
                assert!(
                    matches!(
                        errors.get("url2"),
                        Some(ReadableClientError::ReadChainIdError(msg)) if msg.contains("execution reverted"),
                    ),
                    "url2 error message should contain 'execution reverted' but got: {:?}",
                    errors.get("url2")
                );
            }
            _ => panic!("unexpected error type"),
        }

        Ok(())
    }

    // ---------------------------------------------------------------------
    // Additional tests for the generic `on_providers` helper
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn test_on_providers_success() -> anyhow::Result<()> {
        let asserter1 = Asserter::new();
        let asserter2 = Asserter::new();

        // First provider will fail, second will succeed
        let mock_provider1 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter1.clone());
        let mock_provider2 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter2.clone());

        let mock_error = ErrorPayload {
            code: 3,
            data: None,
            message: "execution reverted".into(),
        };
        asserter1.push_failure(mock_error);
        asserter2.push_success(&5_u64);

        let client = ReadableClient::new(HashMap::from([
            ("url1".to_string(), mock_provider1),
            ("url2".to_string(), mock_provider2),
        ]))?;

        // Use the helper directly with a lightweight closure.
        let chain_id = client
            .on_providers(|provider| async move {
                provider
                    .get_chain_id()
                    .await
                    .map_err(|err| ReadableClientError::ReadChainIdError(err.to_string()))
            })
            .await?;

        assert_eq!(chain_id, 5_u64);

        Ok(())
    }

    #[tokio::test]
    async fn test_on_providers_all_fail() -> anyhow::Result<()> {
        let asserter1 = Asserter::new();
        let asserter2 = Asserter::new();

        let mock_provider1 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter1.clone());
        let mock_provider2 = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter2.clone());

        let mock_error = ErrorPayload {
            code: 3,
            data: None,
            message: "execution reverted".into(),
        };
        asserter1.push_failure(mock_error.clone());
        asserter2.push_failure(mock_error);

        let client = ReadableClient::new(HashMap::from([
            ("url1".to_string(), mock_provider1),
            ("url2".to_string(), mock_provider2),
        ]))?;

        let res = client
            .on_providers(|provider| async move {
                provider
                    .get_chain_id()
                    .await
                    .map_err(|err| ReadableClientError::ReadChainIdError(err.to_string()))
            })
            .await;

        match res {
            Err(ReadableClientError::AllProvidersFailed(errors)) => {
                assert_eq!(errors.len(), 2);
                assert!(errors.iter().all(|(_, e)| matches!(e, ReadableClientError::ReadChainIdError(msg) if msg.contains("execution reverted"))));
            }
            _ => panic!("expected aggregated error"),
        }

        Ok(())
    }
}
