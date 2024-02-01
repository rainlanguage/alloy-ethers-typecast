use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use derive_builder::Builder;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::signer::SignerMiddlewareError;
use ethers::providers::{Middleware, PendingTransaction, ProviderError};
use ethers::signers::Signer;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Bytes, TransactionReceipt};
use ethers::utils::hex;
use thiserror::Error;
use tracing::info;

const DEFAULT_CONFIRMATIONS: u8 = 4;

#[derive(Error, Debug)]
pub enum WritableClientError<M: Middleware, S: Signer> {
    #[error("Transaction did not receive {0} confirmations")]
    WriteConfirmTxError(u8),
    #[error(transparent)]
    SignerMiddlewareError(#[from] SignerMiddlewareError<M, S>),
    #[error(transparent)]
    ProviderError(#[from] ProviderError),
}

#[derive(Builder, Clone, Debug)]
pub struct WriteContractParameters<C: SolCall> {
    pub call: C,
    pub address: Address,
    #[builder(setter(into), default)]
    pub gas: Option<U256>,
    #[builder(setter(into), default)]
    pub gas_price: Option<U256>,
    #[builder(setter(into), default)]
    pub max_fee_per_gas: Option<U256>,
    #[builder(setter(into), default)]
    pub max_priority_fee_per_gas: Option<U256>,
    #[builder(setter(into), default)]
    pub nonce: Option<U256>,
    #[builder(setter(into), default)]
    pub value: Option<U256>,
}
#[derive(Clone)]
pub struct WritableClient<M: Middleware, S: Signer>(SignerMiddleware<M, S>);

impl<M: Middleware, S: Signer> WritableClient<M, S> {
    // Create a new WriteContract instance, passing a client
    pub fn new(client: SignerMiddleware<M, S>) -> Self {
        Self(client)
    }

    // Executes a write function on a contract.
    pub async fn write<C: SolCall>(
        &self,
        parameters: WriteContractParameters<C>,
    ) -> Result<TransactionReceipt, WritableClientError<M, S>> {
        let pending_tx = self.write_pending(parameters).await?;

        info!("Transaction submitted. Awaiting block confirmations...");

        let tx_confirmation = pending_tx
            .confirmations(DEFAULT_CONFIRMATIONS as usize)
            .await?;

        let tx_receipt = match tx_confirmation {
            Some(receipt) => receipt,
            None => {
                return Err(WritableClientError::<M, S>::WriteConfirmTxError(
                    DEFAULT_CONFIRMATIONS,
                ))
            }
        };

        info!("Transaction Confirmed");
        info!(
            "✅ Hash : 0x{}",
            hex::encode(tx_receipt.transaction_hash.as_bytes())
        );
        Ok(tx_receipt)
    }

    // Executes a write function but returns a PendingTransaction instance
    pub async fn write_pending<C: SolCall>(
        &self,
        parameters: WriteContractParameters<C>,
    ) -> Result<ethers::providers::PendingTransaction<'_, M::Provider>, WritableClientError<M, S>>
    {
        let transaction_request = AlloyTransactionRequest::new()
            .with_to(Some(parameters.address))
            .with_data(Some(parameters.call.abi_encode()))
            .with_gas(parameters.gas)
            .with_max_fee_per_gas(parameters.max_fee_per_gas)
            .with_max_priority_fee_per_gas(parameters.max_priority_fee_per_gas)
            .with_nonce(parameters.nonce)
            .with_value(parameters.value);

        let ethers_transaction_request = transaction_request.to_eip1559();

        let pending_tx = self
            .0
            .send_transaction(ethers_transaction_request, None)
            .await?;

        Ok(pending_tx)
    }

    pub async fn prepare_request<C: SolCall>(
        &self,
        parameters: WriteContractParameters<C>,
    ) -> Result<TypedTransaction, WritableClientError<M, S>> {
        let transaction_request = AlloyTransactionRequest::new()
            .with_to(Some(parameters.address))
            .with_data(Some(parameters.call.abi_encode()))
            .with_gas(parameters.gas)
            .with_max_fee_per_gas(parameters.max_fee_per_gas)
            .with_max_priority_fee_per_gas(parameters.max_priority_fee_per_gas)
            .with_nonce(parameters.nonce)
            .with_value(parameters.value);

        let eip1559_request = transaction_request.to_eip1559();

        let mut tx = TypedTransaction::Eip1559(eip1559_request);
        self.0.fill_transaction(&mut tx, None).await?;

        Ok(tx)
    }

    pub async fn sign_request(
        &self,
        tx: TypedTransaction,
    ) -> Result<Bytes, WritableClientError<M, S>> {
        let signature = self
            .0
            .sign_transaction(&tx, self.0.signer().address())
            .await?;

        Ok(tx.rlp_signed(&signature))
    }

    pub async fn send_request(
        &self,
        bytes: Bytes,
    ) -> Result<PendingTransaction<'_, M::Provider>, WritableClientError<M, S>> {
        Ok(self.0.send_raw_transaction(bytes).await?)
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::mock_middleware::{MockJsonRpcClient, MockMiddleware};

    use super::*;
    use alloy_primitives::{Address, U256};
    use alloy_sol_types::sol;
    use ethers::core::rand::thread_rng;
    use ethers::providers::Provider;
    use ethers::signers::LocalWallet;
    use ethers::types::{Bytes, H160};
    use tracing_subscriber;
    use tracing_subscriber::FmtSubscriber;

    sol! {
       function foo(uint256 a, uint256 b) external view returns (Foo);

        struct Foo {
            uint256 bar;
            address baz;
        }
    }

    #[tokio::test]
    async fn test_builder() -> anyhow::Result<()> {
        // without any of the optional parameters
        let parameters = WriteContractParametersBuilder::default()
            .address(Address::repeat_byte(0x11))
            .call(fooCall {
                a: U256::from(42),
                b: U256::from(10),
            })
            .build()?;

        assert_eq!(parameters.address, Address::repeat_byte(0x11));
        assert_eq!(parameters.call.a, U256::from(42));
        assert_eq!(parameters.call.b, U256::from(10));

        // with all the optional parameters
        let parameters = WriteContractParametersBuilder::default()
            .address(Address::repeat_byte(0x11))
            .call(fooCall {
                a: U256::from(42),
                b: U256::from(10),
            })
            .gas(Some(U256::from(100000)))
            .gas_price(Some(U256::from(100000)))
            .max_fee_per_gas(Some(U256::from(100000)))
            .max_priority_fee_per_gas(U256::from(100000))
            .nonce(Some(U256::from(100000)))
            .value(Some(U256::from(100000)))
            .build()?;

        assert_eq!(parameters.address, Address::repeat_byte(0x11));
        assert_eq!(parameters.call.a, U256::from(42));
        assert_eq!(parameters.call.b, U256::from(10));

        Ok(())
    }

    #[tokio::test]
    async fn test_write() -> anyhow::Result<()> {
        // Create a mock transport
        let mock_transport = MockJsonRpcClient::new();
        // Create a Provider instance
        let provider = Provider::new(mock_transport);
        // Create a mock middleware
        let mut mock_middleware = MockMiddleware::new(provider)?;
        // Create a mock wallet
        let wallet = LocalWallet::new(&mut thread_rng());

        // Create a WriteContractParameters instance
        let parameters = WriteContractParametersBuilder::default()
            .call(fooCall {
                a: U256::from(42), // these could be anything, the mock provider doesn't care
                b: U256::from(10),
            })
            .address(Address::repeat_byte(0x22))
            .build()?;

        // Create a mock response
        mock_middleware.assert_next_data(Bytes::from(parameters.call.abi_encode()));
        mock_middleware.assert_next_to(H160::repeat_byte(0x22));

        // Finally create a client SignerMiddleware instance
        let client = SignerMiddleware::new(mock_middleware, wallet);

        // Create a WritableClient instance with the mock client
        let writable_client = WritableClient::new(client);

        // Call the write method
        let _ = writable_client.write(parameters).await?;

        Ok(())
    }

    #[allow(dead_code)]
    fn setup_tracing() {
        let subscriber = FmtSubscriber::builder()
            .with_max_level(tracing::Level::DEBUG)
            .finish();

        tracing::subscriber::set_global_default(subscriber)
            .expect("Failed to set tracing subscriber");
    }
}
