use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use crate::{alloy_u64_to_ethers, ethers_u256_to_alloy};
use alloy_primitives::{Address, U256, U64};
use alloy_sol_types::SolCall;
use derive_builder::Builder;
use ethers::providers::{Http, JsonRpcClient, Middleware, Provider};
use ethers::types::transaction::eip2718::TypedTransaction;
use thiserror::Error;
use tracing::info;
#[derive(Error, Debug)]
pub enum ReadableClientError {
    #[error("failed to instantiate provider: {0}")]
    CreateReadableClientHttpError(String),
    #[error("failed to read call: {0}")]
    ReadCallError(String),
    #[error("failed to decode return: {0}")]
    ReadDecodeReturnError(String),
    #[error("failed to get chain id: {0}")]
    ReadChainIdError(String),
}

#[derive(Builder)]
pub struct ReadContractParameters<C: SolCall> {
    pub address: Address,
    pub call: C,
    #[builder(setter(into), default)]
    pub gas: Option<U256>,
    #[builder(setter(into), default)]
    pub block_number: Option<U64>,
}

#[derive(Clone)]
pub struct ReadableClient<P: JsonRpcClient>(Provider<P>);

pub type ReadableClientHttp = ReadableClient<Http>;

impl ReadableClient<Http> {
    pub fn new_from_url(url: String) -> Result<Self, ReadableClientError> {
        let provider = Provider::<Http>::try_from(url)
            .map_err(|err| ReadableClientError::CreateReadableClientHttpError(err.to_string()))?;
        Ok(Self(provider))
    }
}

impl<P: JsonRpcClient> ReadableClient<P> {
    // Create a new ReadableClient instance, passing a client
    pub fn new(client: Provider<P>) -> Self {
        Self(client)
    }

    // Executes a read function on a contract.
    pub async fn read<C: SolCall>(
        &self,
        parameters: ReadContractParameters<C>,
    ) -> Result<<C as SolCall>::Return, ReadableClientError> {
        let data = parameters.call.abi_encode();

        let transaction_request = AlloyTransactionRequest::new()
            .with_to(Some(parameters.address))
            .with_gas(parameters.gas)
            .with_data(Some(data));

        let res = self
            .0
            .call(
                &TypedTransaction::Eip1559(transaction_request.to_eip1559()),
                parameters.block_number.map(|val| {
                    ethers::types::BlockId::Number(ethers::types::BlockNumber::Number(
                        alloy_u64_to_ethers(val),
                    ))
                }),
            )
            .await
            .map_err(|err| ReadableClientError::ReadCallError(err.to_string()))?;

        info!("response is {:?}", res);
        let return_typed = C::abi_decode_returns(res.to_vec().as_slice(), true)
            .map_err(|err| ReadableClientError::ReadDecodeReturnError(err.to_string()))?;

        Ok(return_typed)
    }

    pub async fn get_chainid(&self) -> Result<U256, ReadableClientError> {
        let chainid = self
            .0
            .get_chainid()
            .await
            .map_err(|err| ReadableClientError::ReadChainIdError(err.to_string()))?;

        Ok(ethers_u256_to_alloy(chainid))
    }

    pub fn inner(&self) -> &Provider<P> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use alloy_sol_types::sol;
    use ethers::providers::{MockProvider, MockResponse};
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
        let read_contract = ReadableClient::new(client);

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
        let read_contract = ReadableClient::new(client);
        let res = read_contract.get_chainid().await.unwrap();

        assert_eq!(res, U256::from(5));

        Ok(())
    }
}
