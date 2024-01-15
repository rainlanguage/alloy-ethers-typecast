use crate::alloy_u64_to_ethers;
use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use alloy_primitives::{Address, U256, U64};
use alloy_sol_types::SolCall;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{JsonRpcClient, Middleware, Provider, ProviderError};
use ethers::signers::Signer;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::TransactionReceipt;
use ethers::utils::hex;
use tracing::info;

pub struct WriteContractParameters<C: SolCall> {
    pub call: Option<C>,
    pub address: Option<Address>,
    pub gas: Option<U256>,
    pub gas_price: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub nonce: Option<U256>,
    pub value: Option<U256>,
}

impl<C: SolCall> WriteContractParameters<C> {
    pub fn default() -> Self {
        Self {
            call: None,
            address: None,
            gas: None,
            gas_price: None,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            nonce: None,
            value: None,
        }
    }

    /// Sets the `call` field in the transaction to the provided value
    /// The call must implement the `SolCall` trait
    pub fn with_call(mut self, call: C) -> Self {
        self.call = Some(call);
        self
    }

    /// Sets the `address` field in the transaction to the provided value
    pub fn with_address<T: Into<Address>>(mut self, address: T) -> Self {
        self.address = Some(address.into());
        self
    }

    /// Sets the `gas` field in the transaction to the provided value
    pub fn with_gas<T: Into<U256>>(mut self, gas: Option<T>) -> Self {
        self.gas = gas.map(|val| val.into());
        self
    }

    /// Sets the `gas_price` field in the transaction to the provided value
    pub fn with_gas_price<T: Into<U256>>(mut self, gas_price: Option<T>) -> Self {
        self.gas_price = gas_price.map(|val| val.into());
        self
    }

    /// Sets the `max_priority_fee_per_gas` field in the transaction to the provided value
    pub fn with_max_priority_fee_per_gas<T: Into<U256>>(
        mut self,
        max_priority_fee_per_gas: Option<T>,
    ) -> Self {
        self.max_priority_fee_per_gas = max_priority_fee_per_gas.map(|val| val.into());
        self
    }

    /// Sets the `max_fee_per_gas` field in the transaction to the provided value
    pub fn with_max_fee_per_gas<T: Into<U256>>(mut self, max_fee_per_gas: Option<T>) -> Self {
        self.max_fee_per_gas = max_fee_per_gas.map(|val| val.into());
        self
    }

    /// Sets the `nonce` field in the transaction to the provided value
    pub fn with_nonce<T: Into<U256>>(mut self, nonce: Option<T>) -> Self {
        self.nonce = nonce.map(|val| val.into());
        self
    }

    /// Sets the `value` field in the transaction to the provided value
    pub fn with_value<T: Into<U256>>(mut self, value: Option<T>) -> Self {
        self.value = value.map(|val| val.into());
        self
    }
}

pub struct WriteContract<M: Middleware, S: Signer> {
    pub client: SignerMiddleware<M, S>,
}

impl<M: Middleware, S: Signer> WriteContract<M, S> {
    // Create a new WriteContract instance, passing a client
    pub fn new(client: SignerMiddleware<M, S>) -> Self {
        Self { client }
    }

    // Executes a write function on a contract.
    pub async fn write<C: SolCall>(
        &self,
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
            .client
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

/// Parameters for sending a transaction
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReadContractParameters<C: SolCall> {
    pub address: Option<Address>,
    pub call: Option<C>,
    pub block_number: Option<U64>,
}

impl<C: SolCall> ReadContractParameters<C> {
    pub fn default() -> Self {
        Self {
            address: None,
            call: None,
            block_number: None,
        }
    }

    /// Sets the `call` field in the transaction to the provided value
    /// The call must implement the `SolCall` trait
    pub fn with_call(mut self, call: C) -> Self {
        self.call = Some(call);
        self
    }

    /// Sets the `address` field in the transaction to the provided value
    pub fn with_address<T: Into<Address>>(mut self, address: T) -> Self {
        self.address = Some(address.into());
        self
    }

    /// Sets the `block_number` field in the transaction to the provided value
    /// If no value is provided, the latest block number will be used
    pub fn with_block_number<T: Into<U64>>(mut self, block_number: Option<T>) -> Self {
        self.block_number = block_number.map(|val| val.into());
        self
    }
}

pub struct ReadContract<P: JsonRpcClient> {
    pub client: Provider<P>,
}

impl<P: JsonRpcClient> ReadContract<P> {
    // Create a new ReadContract instance, passing a client
    pub fn new(client: Provider<P>) -> Self {
        Self { client }
    }

    // Executes a read function on a contract.
    pub async fn read<C: SolCall>(
        &self,
        parameters: ReadContractParameters<C>,
    ) -> anyhow::Result<<C as SolCall>::Return> {
        let data = parameters
            .call
            .ok_or(anyhow::anyhow!("No call provided"))?
            .abi_encode();

        let transaction_request = AlloyTransactionRequest::new()
            .with_to(parameters.address)
            .with_data(Some(data));

        let ethers_transaction_request = transaction_request.to_eip1559();

        let res = self
            .client
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

        // Create a ReadContract instance with the mock provider
        let read_contract = ReadContract::new(client);

        // Create a ReadContractParameters instance
        let parameters = ReadContractParameters::<fooCall>::default()
            .with_call(fooCall {
                a: U256::from(42), // these could be anything, the mock provider doesn't care
                b: U256::from(10),
            })
            .with_address(Address::repeat_byte(0x22))
            .with_block_number(Some(U64::from(123)));

        // Call the read method
        let result = read_contract.read(parameters).await?;

        let bar = result._0.bar;
        let baz = result._0.baz;

        assert_eq!(bar, U256::from(42));
        assert_eq!(baz, Address::repeat_byte(0x11));

        Ok(())
    }
}
