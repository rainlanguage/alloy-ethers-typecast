use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use crate::{alloy_u64_to_ethers, ethers_u256_to_alloy};
use alloy::primitives::{Address, U256, U64};
use alloy::sol_types::SolCall;
use derive_builder::Builder;
use ethers::providers::{Http, JsonRpcClient, Middleware, Provider, ProviderError};
use ethers::types::transaction::eip2718::TypedTransaction;
use std::collections::HashMap;
use thiserror::Error;

use rain_error_decoding::{AbiDecodeFailedErrors, AbiDecodedErrorType};

#[derive(Error, Debug)]
pub enum ReadableClientError {
    #[error("failed to instantiate provider: {0}")]
    CreateReadableClientHttpError(String),
    #[error(transparent)]
    ReadCallError(ProviderError),
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
    #[error("rpc provider {0} failed to handle the request: {1}")]
    RpcProviderFailed(String, String),
}

#[derive(Builder)]
pub struct ReadContractParameters<C: SolCall> {
    pub address: Address,
    pub call: C,
    #[builder(setter(into), default)]
    pub block_number: Option<U64>,
    #[builder(setter(into), default)]
    pub gas: Option<U256>,
}

#[derive(Clone)]
pub struct ReadableClient<P: JsonRpcClient> {
    providers: HashMap<String, Provider<P>>,
}

pub type ReadableClientHttp = ReadableClient<Http>;

impl ReadableClient<Http> {
    pub fn new_from_urls(urls: Vec<String>) -> Result<Self, ReadableClientError> {
        let providers: HashMap<String, _> = urls
            .into_iter()
            .filter_map(|url| {
                Provider::<Http>::try_from(url.clone())
                    .ok()
                    .map(|provider| (url, provider))
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
}

impl<P: JsonRpcClient> ReadableClient<P> {
    pub fn new(providers: HashMap<String, Provider<P>>) -> Self {
        Self { providers }
    }

    // Executes a read function on a contract.
    pub async fn read<C: SolCall>(
        &self,
        parameters: ReadContractParameters<C>,
    ) -> Result<<C as SolCall>::Return, ReadableClientError> {
        let data = parameters.call.abi_encode();

        let transaction_request = AlloyTransactionRequest::new()
            .with_to(Some(parameters.address))
            .with_data(Some(data))
            .with_gas(parameters.gas);

        let mut errors: HashMap<String, ReadableClientError> = HashMap::new();

        for (url, provider) in &self.providers {
            let typed_tx = TypedTransaction::Eip1559(transaction_request.to_eip1559());
            let block_id = parameters.block_number.map(|val| {
                ethers::types::BlockId::Number(ethers::types::BlockNumber::Number(
                    alloy_u64_to_ethers(val),
                ))
            });

            match provider.call(&typed_tx, block_id).await {
                Ok(res) => {
                    return C::abi_decode_returns(res.to_vec().as_slice(), true).map_err(|err| {
                        ReadableClientError::ReadDecodeReturnError(err.to_string())
                    });
                }
                Err(provider_err) => {
                    match AbiDecodedErrorType::try_from_provider_error(provider_err).await {
                        Ok(decoded_err) => {
                            errors.insert(
                                url.clone(),
                                ReadableClientError::AbiDecodedErrorType(decoded_err),
                            );
                        }
                        Err(decode_failed_err) => {
                            errors.insert(
                                url.clone(),
                                ReadableClientError::AbiDecodeFailedErrors(decode_failed_err),
                            );
                        }
                    }
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

    pub async fn get_chainid(&self) -> Result<U256, ReadableClientError> {
        let mut errors: HashMap<String, ReadableClientError> = HashMap::new();

        for (url, provider) in &self.providers {
            let res = provider
                .get_chainid()
                .await
                .map_err(|err| ReadableClientError::ReadChainIdError(err.to_string()));

            if let Ok(chainid) = res {
                return Ok(ethers_u256_to_alloy(chainid));
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
                return Ok(block_number.as_u64());
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
    use alloy::primitives::{hex::encode, Address, U256};
    use alloy::sol;
    use ethers::providers::{JsonRpcError, MockProvider, MockResponse};
    use serde_json::json;

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
        // Create a mock Provider
        let mock_provider = MockProvider::new();

        let bytes_string = "0x000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000001111111111111111111111111111111111111111";

        // Create a mock response
        let foo_response = json!(bytes_string);

        let mock_response = MockResponse::Value(foo_response);
        mock_provider.push_response(mock_response.clone());
        mock_provider.push_response(mock_response.clone());
        mock_provider.push_response(mock_response);

        // Create a Provider instance with the mock provider
        let client = Provider::new(mock_provider);

        // Create a ReadableClient instance with the mock provider
        let read_contract = ReadableClient::new(HashMap::from([("url".to_string(), client)]));

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

        let bar = result._0.bar;
        let baz = result._0.baz;

        assert_eq!(bar, U256::from(42));
        assert_eq!(baz, Address::repeat_byte(0x11));

        Ok(())
    }

    #[tokio::test]
    async fn test_get_chainid() -> anyhow::Result<()> {
        // Create a mock Provider
        let mock_provider = MockProvider::new();

        // Create a mock response
        let foo_response =
            json!("0x0000000000000000000000000000000000000000000000000000000000000005");

        let mock_response = MockResponse::Value(foo_response);
        mock_provider.push_response(mock_response);

        // Create a Provider instance with the mock provider
        let client = Provider::new(mock_provider);

        // Create a ReadableClient instance with the mock provider
        let read_contract = ReadableClient::new(HashMap::from([("url".to_string(), client)]));
        let res = read_contract.get_chainid().await.unwrap();

        assert_eq!(res, U256::from(5));

        Ok(())
    }

    #[tokio::test]
    async fn test_get_block_number() -> anyhow::Result<()> {
        // Create a mock Provider
        let mock_provider = MockProvider::new();

        // Create a mock response
        let foo_response = json!("0x0000006");

        let mock_response = MockResponse::Value(foo_response);
        mock_provider.push_response(mock_response);

        // Create a Provider instance with the mock provider
        let client = Provider::new(mock_provider);

        // Create a ReadableClient instance with the mock provider
        let read_contract = ReadableClient::new(HashMap::from([("url".to_string(), client)]));
        let res = read_contract.get_block_number().await.unwrap();

        assert_eq!(res, 6_u64);

        Ok(())
    }

    #[tokio::test]
    async fn test_decodable_error() -> anyhow::Result<()> {
        // Create a mock Provider
        let mock_provider = MockProvider::new();

        let data = vec![26, 198, 105, 8];
        let mock_error = JsonRpcError {
            code: 3,
            data: Some(json!(encode(&data))),
            message: "execution reverted".to_string(),
        };

        let mock_response = MockResponse::Error(mock_error);
        mock_provider.push_response(mock_response);

        // Create a Provider instance with the mock provider
        let client = Provider::new(mock_provider);

        // Create a ReadableClient instance with the mock provider
        let read_contract = ReadableClient::new(HashMap::from([("url".to_string(), client)]));

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
        let mock_provider1 = MockProvider::new();
        let mock_provider2 = MockProvider::new();
        let mock_provider3 = MockProvider::new();

        let foo_response = json!("0x000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000001111111111111111111111111111111111111111");
        let mock_response = MockResponse::Value(foo_response);
        let mock_error = MockResponse::Error(JsonRpcError {
            code: 3,
            data: None,
            message: "execution reverted".to_string(),
        });

        mock_provider1.push_response(mock_error.clone());
        mock_provider2.push_response(mock_error.clone());
        mock_provider3.push_response(mock_response);

        let client1 = Provider::new(mock_provider1);
        let client2 = Provider::new(mock_provider2);
        let client3 = Provider::new(mock_provider3);

        let read_contract = ReadableClient::new(HashMap::from([
            ("url1".to_string(), client1),
            ("url2".to_string(), client2),
            ("url3".to_string(), client3),
        ]));

        let parameters = ReadContractParametersBuilder::default()
            .call(fooCall {
                a: U256::from(42), // these could be anything, the mock provider doesn't care
                b: U256::from(10),
            })
            .address(Address::repeat_byte(0x22))
            .build()?;
        let result = read_contract.read(parameters).await?;

        let bar = result._0.bar;
        let baz = result._0.baz;
        assert_eq!(bar, U256::from(42));
        assert_eq!(baz, Address::repeat_byte(0x11));

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_providers_read_error() -> anyhow::Result<()> {
        let mock_provider1 = MockProvider::new();
        let mock_provider2 = MockProvider::new();
        let mock_provider3 = MockProvider::new();
        let mock_provider4 = MockProvider::new();

        mock_provider1.push_response(MockResponse::Error(JsonRpcError {
            code: 3,
            data: None,
            message: "execution reverted".to_string(),
        }));
        mock_provider2.push_response(MockResponse::Error(JsonRpcError {
            code: 3,
            data: Some(json!(encode(vec![26, 198, 105, 8]))),
            message: "some other error".to_string(),
        }));
        mock_provider3.push_response(MockResponse::Error(JsonRpcError {
            code: 3,
            data: Some(json!({"error": "some other error"})),
            message: "some other error".to_string(),
        }));
        mock_provider4.push_response(MockResponse::Error(JsonRpcError {
            code: 3,
            data: Some(json!(&vec![1])),
            message: "some other error".to_string(),
        }));

        let client1 = Provider::new(mock_provider1);
        let client2 = Provider::new(mock_provider2);
        let client3 = Provider::new(mock_provider3);
        let client4 = Provider::new(mock_provider4);

        let read_contract = ReadableClient::new(HashMap::from([
            ("url4".to_string(), client1),
            ("url5".to_string(), client2),
            ("url6".to_string(), client3),
            ("url7".to_string(), client4),
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

                assert!(errors.contains_key("url4"));
                match errors.get("url4") {
                    Some(ReadableClientError::AbiDecodedErrorType(
                        AbiDecodedErrorType::Unknown(data),
                    )) => {
                        assert_eq!(data, &Vec::<u8>::new());
                    }
                    _ => panic!("unexpected error type"),
                }

                assert!(errors.contains_key("url5"));
                match errors.get("url5") {
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

                assert!(errors.contains_key("url6"));
                match errors.get("url6") {
                    Some(ReadableClientError::AbiDecodedErrorType(
                        AbiDecodedErrorType::Unknown(data),
                    )) => {
                        assert_eq!(data, &Vec::<u8>::new());
                    }
                    _ => panic!("unexpected error type"),
                }

                assert!(errors.contains_key("url7"));
                match errors.get("url7") {
                    Some(ReadableClientError::AbiDecodedErrorType(
                        AbiDecodedErrorType::Unknown(data),
                    )) => {
                        assert_eq!(data, &Vec::<u8>::new());
                    }
                    _ => panic!("unexpected error type"),
                }
            }
            _ => panic!("unexpected error type"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_providers_get_block_number() -> anyhow::Result<()> {
        let mock_provider1 = MockProvider::new();
        let mock_provider2 = MockProvider::new();
        let mock_provider3 = MockProvider::new();

        let foo_response = json!("0x0000006");
        let mock_response = MockResponse::Value(foo_response);
        let mock_error = MockResponse::Error(JsonRpcError {
            code: 3,
            data: None,
            message: "execution reverted".to_string(),
        });

        mock_provider1.push_response(mock_error.clone());
        mock_provider2.push_response(mock_error.clone());
        mock_provider3.push_response(mock_response);

        let client1 = Provider::new(mock_provider1);
        let client2 = Provider::new(mock_provider2);
        let client3 = Provider::new(mock_provider3);

        let read_contract = ReadableClient::new(HashMap::from([
            ("url1".to_string(), client1),
            ("url2".to_string(), client2),
            ("url3".to_string(), client3),
        ]));

        let res = read_contract.get_block_number().await.unwrap();
        assert_eq!(res, 6_u64);

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_providers_get_block_number_error() -> anyhow::Result<()> {
        let mock_provider1 = MockProvider::new();
        let mock_provider2 = MockProvider::new();

        let mock_error = MockResponse::Error(JsonRpcError {
            code: 3,
            data: None,
            message: "execution reverted".to_string(),
        });
        mock_provider1.push_response(mock_error.clone());
        mock_provider2.push_response(mock_error.clone());

        let client1 = Provider::new(mock_provider1);
        let client2 = Provider::new(mock_provider2);

        let read_contract = ReadableClient::new(HashMap::from([
            ("url1".to_string(), client1),
            ("url2".to_string(), client2),
        ]));

        let res = read_contract.get_block_number().await;
        let err = res.err().unwrap();
        match err {
            ReadableClientError::AllProvidersFailed(errors) => {
                assert_eq!(errors.len(), 2);

                assert!(errors.contains_key("url1"));
                match errors.get("url1") {
                    Some(ReadableClientError::ReadBlockNumberError(error)) => {
                        assert_eq!(
                            error,
                            "JSON-RPC error: (code: 3, message: execution reverted, data: None)"
                        );
                    }
                    _ => panic!("unexpected error type"),
                }

                assert!(errors.contains_key("url2"));
                match errors.get("url2") {
                    Some(ReadableClientError::ReadBlockNumberError(error)) => {
                        assert_eq!(
                            error,
                            "JSON-RPC error: (code: 3, message: execution reverted, data: None)"
                        );
                    }
                    _ => panic!("unexpected error type"),
                }
            }
            _ => panic!("unexpected error type"),
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_providers_get_chainid() -> anyhow::Result<()> {
        let mock_provider1 = MockProvider::new();
        let mock_provider2 = MockProvider::new();
        let mock_provider3 = MockProvider::new();

        let foo_response = json!("0x00000005");
        let mock_response = MockResponse::Value(foo_response);
        let mock_error = MockResponse::Error(JsonRpcError {
            code: 3,
            data: None,
            message: "execution reverted".to_string(),
        });

        mock_provider1.push_response(mock_error.clone());
        mock_provider2.push_response(mock_error.clone());
        mock_provider3.push_response(mock_response);

        let client1 = Provider::new(mock_provider1);
        let client2 = Provider::new(mock_provider2);
        let client3 = Provider::new(mock_provider3);

        let read_contract = ReadableClient::new(HashMap::from([
            ("url1".to_string(), client1),
            ("url2".to_string(), client2),
            ("url3".to_string(), client3),
        ]));

        let res = read_contract.get_chainid().await.unwrap();
        assert_eq!(res, U256::from(5));

        Ok(())
    }

    #[tokio::test]
    async fn test_multiple_providers_get_chainid_error() -> anyhow::Result<()> {
        let mock_provider1 = MockProvider::new();
        let mock_provider2 = MockProvider::new();

        let mock_error = MockResponse::Error(JsonRpcError {
            code: 3,
            data: None,
            message: "execution reverted".to_string(),
        });
        mock_provider1.push_response(mock_error.clone());
        mock_provider2.push_response(mock_error.clone());

        let client1 = Provider::new(mock_provider1);
        let client2 = Provider::new(mock_provider2);

        let read_contract = ReadableClient::new(HashMap::from([
            ("url1".to_string(), client1),
            ("url2".to_string(), client2),
        ]));

        let res = read_contract.get_chainid().await;
        let err = res.err().unwrap();
        match err {
            ReadableClientError::AllProvidersFailed(errors) => {
                assert_eq!(errors.len(), 2);

                assert!(errors.contains_key("url1"));
                match errors.get("url1") {
                    Some(ReadableClientError::ReadChainIdError(error)) => {
                        assert_eq!(
                            error,
                            "JSON-RPC error: (code: 3, message: execution reverted, data: None)"
                        );
                    }
                    _ => panic!("unexpected error type"),
                }

                assert!(errors.contains_key("url2"));
                match errors.get("url2") {
                    Some(ReadableClientError::ReadChainIdError(error)) => {
                        assert_eq!(
                            error,
                            "JSON-RPC error: (code: 3, message: execution reverted, data: None)"
                        );
                    }
                    _ => panic!("unexpected error type"),
                }
            }
            _ => panic!("unexpected error type"),
        }

        Ok(())
    }
}
