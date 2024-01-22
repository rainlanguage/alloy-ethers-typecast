use alloy_sol_types::SolCall;
use ethers::middleware::SignerMiddleware;
use ethers::providers::Middleware;
use ethers::signers::Signer;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Bytes, TransactionReceipt};

use crate::transaction::{WritableClient, WritableClientError, WriteContractParameters};

#[derive(Clone, Debug)]
pub enum WriteTransactionStatus<C: SolCall> {
    PendingPrepare(WriteContractParameters<C>),
    PendingSign(TypedTransaction),
    PendingSend(Bytes),
    Confirmed(TransactionReceipt),
}

pub struct WriteTransaction<
    M: Middleware,
    S: Signer,
    C: SolCall + Clone,
    F: Fn(WriteTransactionStatus<C>),
> {
    pub client: WritableClient<M, S>,
    pub status: WriteTransactionStatus<C>,
    pub confirmations: u8,
    pub status_changed: F,
}

impl<M: Middleware, S: Signer, C: SolCall + Clone, F: Fn(WriteTransactionStatus<C>)>
    WriteTransaction<M, S, C, F>
{
    pub fn new(
        client: SignerMiddleware<M, S>,
        parameters: WriteContractParameters<C>,
        confirmations: u8,
        status_changed: F,
    ) -> Self {
        Self {
            client: WritableClient::new(client),
            status: WriteTransactionStatus::<C>::PendingPrepare(parameters),
            confirmations,
            status_changed,
        }
    }

    pub async fn execute(&mut self) -> Result<(), WritableClientError> {
        self.prepare().await?;
        self.sign().await?;
        self.send().await?;
        Ok(())
    }

    async fn prepare(&mut self) -> Result<(), WritableClientError> {
        if let WriteTransactionStatus::PendingPrepare(parameters) = &self.status {
            let tx_request = self.client.prepare_request(parameters.clone()).await?;
            self.update_status(WriteTransactionStatus::PendingSign(tx_request));
        }
        Ok(())
    }

    async fn sign(&mut self) -> Result<(), WritableClientError> {
        if let WriteTransactionStatus::PendingSign(tx_request) = &self.status {
            let signed_tx = self.client.sign_request(tx_request.clone()).await?;
            self.update_status(WriteTransactionStatus::PendingSend(signed_tx));
        }
        Ok(())
    }

    async fn send(&mut self) -> Result<(), WritableClientError> {
        if let WriteTransactionStatus::PendingSend(signed_tx) = &self.status {
            let pending_tx = self.client.send_request(signed_tx.clone()).await?;
            let receipt = pending_tx
                .confirmations(self.confirmations.into())
                .await
                .map_err(|e| WritableClientError::WriteConfirmationError(e.to_string()))?
                .ok_or(WritableClientError::WriteConfirmationError(format!(
                    "Transaction did not receive {} confirmations",
                    self.confirmations,
                )))?;
            self.update_status(WriteTransactionStatus::Confirmed(receipt));
        }
        Ok(())
    }

    fn update_status(&mut self, status: WriteTransactionStatus<C>) {
        self.status = status.clone();
        (self.status_changed)(status);
    }
}

#[cfg(test)]
mod tests {
    use crate::transaction::mock_middleware::{MockJsonRpcClient, MockMiddleware};
    use crate::transaction::WriteContractParametersBuilder;

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
    async fn test_write_transaction() -> anyhow::Result<()> {
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
        WriteTransaction::new(client, parameters, 4, |_| {})
            .execute()
            .await?;

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
