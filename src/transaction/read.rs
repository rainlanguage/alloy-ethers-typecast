use crate::alloy_u64_to_ethers;
use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use alloy_primitives::{Address, U64};
use alloy_sol_types::SolCall;
use derive_builder::Builder;
use ethers::providers::{JsonRpcClient, Middleware, Provider, ProviderError};
use ethers::types::transaction::eip2718::TypedTransaction;

#[derive(Builder)]
pub struct ReadContractParameters<C: SolCall> {
    pub address: Address,
    pub call: C,
    #[builder(setter(into, strip_option))]
    pub block_number: Option<U64>,
}

pub struct ReadableClient<P: JsonRpcClient>(Provider<P>);

impl<P: JsonRpcClient> ReadableClient<P> {
    // Create a new ReadContract instance, passing a client
    pub fn new(client: Provider<P>) -> Self {
        Self(client)
    }

    // Executes a read function on a contract.
    pub async fn read<C: SolCall>(
        self,
        parameters: ReadContractParameters<C>,
    ) -> anyhow::Result<<C as SolCall>::Return> {
        let data = parameters.call.abi_encode();

        let transaction_request = AlloyTransactionRequest::new()
            .with_to(Some(parameters.address))
            .with_data(Some(data));

        let ethers_transaction_request = transaction_request.to_eip1559();

        let res = self
            .0
            .call(
                &TypedTransaction::Eip1559(ethers_transaction_request),
                parameters.block_number.map(|val| {
                    ethers::types::BlockId::Number(ethers::types::BlockNumber::Number(
                        alloy_u64_to_ethers(val),
                    ))
                }),
            )
            .await
            .map_err(|err| match err {
                ProviderError::JsonRpcClientError(err) => {
                    anyhow::anyhow!("{}", err)
                }
                _ => anyhow::anyhow!("{}", err),
            })?;

        let return_typed = C::abi_decode_returns(res.to_vec().as_slice(), true)?;

        Ok(return_typed)
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
            .block_number(U64::from(123))
            .build()?;

        // Call the read method
        let result = read_contract.read(parameters).await?;

        let bar = result._0.bar;
        let baz = result._0.baz;

        assert_eq!(bar, U256::from(42));
        assert_eq!(baz, Address::repeat_byte(0x11));

        Ok(())
    }
}
