use crate::alloy_u64_to_ethers;
use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use alloy_primitives::{Address, U256, U64};
use alloy_sol_types::SolCall;
use derive_builder::Builder;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{JsonRpcClient, Middleware, Provider, ProviderError};
use ethers::signers::Signer;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::TransactionReceipt;
use ethers::utils::hex;
use tracing::info;

#[derive(Builder)]
pub struct WriteContractParameters<C: SolCall + Default> {
    pub call: Option<C>,
    pub address: Option<Address>,
    #[builder(setter(into, strip_option))]
    pub gas: Option<U256>,
    #[builder(setter(into, strip_option))]
    pub gas_price: Option<U256>,
    #[builder(setter(into, strip_option))]
    pub max_fee_per_gas: Option<U256>,
    #[builder(setter(into, strip_option))]
    pub max_priority_fee_per_gas: Option<U256>,
    #[builder(setter(into, strip_option))]
    pub nonce: Option<U256>,
    #[builder(setter(into, strip_option))]
    pub value: Option<U256>,
}

pub struct WritableClient<M: Middleware, S: Signer>(SignerMiddleware<M, S>);

impl<M: Middleware, S: Signer> WritableClient<M, S> {
    // Create a new WriteContract instance, passing a client
    pub fn new(client: SignerMiddleware<M, S>) -> Self {
        Self(client)
    }

    // Executes a write function on a contract.
    pub async fn write<C: SolCall + Default>(
        self,
        parameters: WriteContractParameters<C>,
    ) -> anyhow::Result<TransactionReceipt> {
        let data = parameters
            .call
            .ok_or(anyhow::anyhow!("No call provided"))?
            .abi_encode();

        let transaction_request = AlloyTransactionRequest::new()
            .with_to(parameters.address)
            .with_data(Some(data))
            .with_gas(parameters.gas)
            .with_max_fee_per_gas(parameters.max_fee_per_gas)
            .with_max_priority_fee_per_gas(parameters.max_priority_fee_per_gas)
            .with_nonce(parameters.nonce)
            .with_value(parameters.value);

        let ethers_transaction_request = transaction_request.to_eip1559();

        let pending_tx = self
            .0
            .send_transaction(ethers_transaction_request, None)
            .await
            .map_err(|err| anyhow::anyhow!("{}", err))?;

        info!("Transaction submitted. Awaiting block confirmations...");

        let tx_confirmation = pending_tx.confirmations(4).await?;

        let tx_receipt = match tx_confirmation {
            Some(receipt) => receipt,
            None => return Err(anyhow::anyhow!("Transaction failed")),
        };

        info!("Transaction Confirmed");
        info!(
            "✅ Hash : 0x{}",
            hex::encode(tx_receipt.transaction_hash.as_bytes())
        );
        Ok(tx_receipt)
    }
}

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
