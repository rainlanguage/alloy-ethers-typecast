use alloy::network::{AnyNetwork, TransactionBuilder};
use alloy::primitives::{Address, U64};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::serde::WithOtherFields;
use alloy::sol_types::SolCall;
use alloy::transports::{RpcError, TransportErrorKind};
use derive_builder::Builder;
use std::collections::HashMap;
use thiserror::Error;

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

pub struct ReadableClient {
    providers: HashMap<String, Box<dyn Provider<AnyNetwork>>>,
}

impl ReadableClient {
    pub async fn new_from_url(url: String) -> Result<Self, ReadableClientError> {
        let provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect(&url)
            .await?;

        Ok(Self {
            providers: HashMap::from([(url, Box::new(provider) as Box<dyn Provider<AnyNetwork>>)]),
        })
    }

    pub fn new_from_http_urls(urls: Vec<String>) -> Result<Self, ReadableClientError> {
        let providers: HashMap<String, _> = urls
            .into_iter()
            .filter_map(|url| {
                let rpc_url = url.parse().ok()?;
                let provider: Box<dyn Provider<AnyNetwork>> = Box::new(
                    ProviderBuilder::new()
                        .network::<AnyNetwork>()
                        .connect_http(rpc_url),
                );
                Some((url, provider))
            })
            .collect();

        if providers.is_empty() {
            Err(ReadableClientError::CreateReadableClientHttpError(
                "No valid providers could be created from the given URLs.".to_string(),
            ))
        } else {
            Ok(Self { providers })
        }
    }

    pub fn new(providers: HashMap<String, Box<dyn Provider<AnyNetwork>>>) -> Self {
        Self { providers }
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

        let mut errors: HashMap<String, ReadableClientError> = HashMap::new();

        for (url, provider) in &self.providers {
            match provider
                .call(WithOtherFields::new(transaction_request.clone()))
                .await
            {
                Ok(res) => {
                    return C::abi_decode_returns(res.to_vec().as_slice()).map_err(|err| {
                        ReadableClientError::ReadDecodeReturnError(err.to_string())
                    });
                }
                Err(provider_err) => {
                    let error_to_insert = if let Some(rpc_err) = provider_err.as_error_resp() {
                        match AbiDecodedErrorType::try_from_json_rpc_error(rpc_err.clone()).await {
                            Ok(decoded_err) => {
                                ReadableClientError::AbiDecodedErrorType(decoded_err)
                            }
                            Err(decode_failed_err) => {
                                ReadableClientError::AbiDecodeFailedErrors(decode_failed_err)
                            }
                        }
                    } else {
                        ReadableClientError::RpcTransportKindError(provider_err)
                    };
                    errors.insert(url.clone(), error_to_insert);
                }
            }
        }

        if errors.is_empty() {
            Err(ReadableClientError::CreateReadableClientHttpError(
                "No providers were available to handle the request.".to_string(),
            ))
        } else {
            Err(ReadableClientError::AllProvidersFailed(errors))
        }
    }

    pub async fn get_chainid(&self) -> Result<u64, ReadableClientError> {
        let mut errors: HashMap<String, ReadableClientError> = HashMap::new();

        for (url, provider) in &self.providers {
            let res = provider
                .get_chain_id()
                .await
                .map_err(|err| ReadableClientError::ReadChainIdError(err.to_string()));

            if let Ok(chainid) = res {
                return Ok(chainid);
            } else {
                errors.insert(url.clone(), res.err().unwrap());
            }
        }

        Err(ReadableClientError::AllProvidersFailed(errors))
    }

    pub async fn get_block_number(&self) -> Result<u64, ReadableClientError> {
        let mut errors: HashMap<String, ReadableClientError> = HashMap::new();

        for (url, provider) in &self.providers {
            let res = provider
                .get_block_number()
                .await
                .map_err(|err| ReadableClientError::ReadBlockNumberError(err.to_string()));

            if let Ok(block_number) = res {
                return Ok(block_number);
            } else {
                errors.insert(url.clone(), res.err().unwrap());
            }
        }

        Err(ReadableClientError::AllProvidersFailed(errors))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, U256};
    use alloy::providers::mock::Asserter;
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

        let mock_provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());

        let bytes_string = "0x000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000001111111111111111111111111111111111111111";

        let mock_response = json!(bytes_string);

        asserter.push_success(&mock_response.clone());
        asserter.push_success(&mock_response.clone());
        asserter.push_success(&mock_response);

        // Create a ReadableClient instance with the mock provider
        let read_contract = ReadableClient::new(HashMap::from([(
            "url".to_string(),
            Box::new(mock_provider) as Box<dyn Provider<AnyNetwork>>,
        )]));

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

        let mock_provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());

        asserter.push_success(&5_u64);

        let read_contract = ReadableClient::new(HashMap::from([(
            "url".to_string(),
            Box::new(mock_provider) as Box<dyn Provider<AnyNetwork>>,
        )]));
        let res = read_contract.get_chainid().await.unwrap();

        assert_eq!(res, 5_u64);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_block_number() -> anyhow::Result<()> {
        let asserter = Asserter::new();

        let mock_provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());

        asserter.push_success(&6_u64);

        let read_contract = ReadableClient::new(HashMap::from([(
            "url".to_string(),
            Box::new(mock_provider) as Box<dyn Provider<AnyNetwork>>,
        )]));
        let res = read_contract.get_block_number().await.unwrap();

        assert_eq!(res, 6_u64);

        Ok(())
    }

    #[tokio::test]
    async fn test_decodable_error() -> anyhow::Result<()> {
        let asserter = Asserter::new();

        let mock_provider = ProviderBuilder::new()
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());

        let mock_error = ErrorPayload {
            code: 3,
            data: Some(RawValue::from_string(r#""0x1ac66908""#.to_string()).unwrap()),
            message: "execution reverted".into(),
        };

        asserter.push_failure(mock_error);

        let read_contract = ReadableClient::new(HashMap::from([(
            "url".to_string(),
            Box::new(mock_provider) as Box<dyn Provider<AnyNetwork>>,
        )]));

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

                assert!(errors.contains_key("url"));
                match errors.get("url") {
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
            (
                "url1".to_string(),
                Box::new(mock_provider1) as Box<dyn Provider<AnyNetwork>>,
            ),
            (
                "url2".to_string(),
                Box::new(mock_provider2) as Box<dyn Provider<AnyNetwork>>,
            ),
            (
                "url3".to_string(),
                Box::new(mock_provider3) as Box<dyn Provider<AnyNetwork>>,
            ),
        ]));

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
            (
                "url1".to_string(),
                Box::new(mock_provider1) as Box<dyn Provider<AnyNetwork>>,
            ),
            (
                "url2".to_string(),
                Box::new(mock_provider2) as Box<dyn Provider<AnyNetwork>>,
            ),
            (
                "url3".to_string(),
                Box::new(mock_provider3) as Box<dyn Provider<AnyNetwork>>,
            ),
            (
                "url4".to_string(),
                Box::new(mock_provider4) as Box<dyn Provider<AnyNetwork>>,
            ),
        ]));

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
            (
                "url1".to_string(),
                Box::new(mock_provider1) as Box<dyn Provider<AnyNetwork>>,
            ),
            (
                "url2".to_string(),
                Box::new(mock_provider2) as Box<dyn Provider<AnyNetwork>>,
            ),
            (
                "url3".to_string(),
                Box::new(mock_provider3) as Box<dyn Provider<AnyNetwork>>,
            ),
        ]));

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
            (
                "url1".to_string(),
                Box::new(mock_provider1) as Box<dyn Provider<AnyNetwork>>,
            ),
            (
                "url2".to_string(),
                Box::new(mock_provider2) as Box<dyn Provider<AnyNetwork>>,
            ),
        ]));

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
            (
                "url1".to_string(),
                Box::new(mock_provider1) as Box<dyn Provider<AnyNetwork>>,
            ),
            (
                "url2".to_string(),
                Box::new(mock_provider2) as Box<dyn Provider<AnyNetwork>>,
            ),
            (
                "url3".to_string(),
                Box::new(mock_provider3) as Box<dyn Provider<AnyNetwork>>,
            ),
        ]));

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
            (
                "url1".to_string(),
                Box::new(mock_provider1) as Box<dyn Provider<AnyNetwork>>,
            ),
            (
                "url2".to_string(),
                Box::new(mock_provider2) as Box<dyn Provider<AnyNetwork>>,
            ),
        ]));

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
}
