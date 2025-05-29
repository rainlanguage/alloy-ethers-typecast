use crate::transaction::{WritableClient, WritableClientError, WriteContractParameters};
use alloy::network::{AnyNetwork, NetworkWallet};
use alloy::primitives::Bytes;
use alloy::providers::Provider;
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::sol_types::SolCall;
use std::time::Duration;

const TRANSACTION_RETRY_INTERVAL_SECONDS: u64 = 5;
const TRANSACTION_RETRY_COUNT: usize = 15;

#[derive(Clone, Debug)]
pub enum WriteTransactionStatus<C: SolCall> {
    PendingPrepare(Box<WriteContractParameters<C>>),
    PendingSign(TransactionRequest),
    PendingSend(Bytes),
    Confirmed(Box<TransactionReceipt>),
}

pub struct WriteTransaction<
    P: Provider<AnyNetwork> + Clone,
    C: SolCall + Clone,
    F: Fn(WriteTransactionStatus<C>),
> {
    pub client: WritableClient<P>,
    pub status: WriteTransactionStatus<C>,
    pub confirmations: u8,
    pub status_changed: F,
}

impl<P: Provider<AnyNetwork> + Clone, C: SolCall + Clone, F: Fn(WriteTransactionStatus<C>)>
    WriteTransaction<W, C, F>
{
    pub fn new(
        client: P,
        parameters: WriteContractParameters<C>,
        confirmations: u8,
        status_changed: F,
    ) -> Self {
        Self {
            client: WritableClient::new(client),
            status: WriteTransactionStatus::<C>::PendingPrepare(Box::new(parameters)),
            confirmations,
            status_changed,
        }
    }

    pub async fn execute(&mut self) -> Result<(), WritableClientError> {
        if let WriteTransactionStatus::PendingPrepare(parameters) = &self.status {
            self.update_status(WriteTransactionStatus::PendingPrepare(parameters.clone()));
        }

        self.prepare().await?;
        self.sign().await?;
        self.send().await?;
        Ok(())
    }

    async fn prepare(&mut self) -> Result<(), WritableClientError> {
        if let WriteTransactionStatus::PendingPrepare(parameters) = &self.status {
            let tx_request = parameters.build_transaction_request();
            self.update_status(WriteTransactionStatus::PendingSign(tx_request));
        }
        Ok(())
    }

    async fn send(&mut self) -> Result<(), WritableClientError> {
        if let WriteTransactionStatus::PendingSign(tx_request) = &self.status {
            let pending_tx = self.client.send_request(signed_tx.clone()).await?;
            let receipt = pending_tx
                .interval(Duration::from_secs(TRANSACTION_RETRY_INTERVAL_SECONDS))
                .retries(TRANSACTION_RETRY_COUNT)
                .confirmations(self.confirmations.into())
                .await
                .map_err(WritableClientError::WriteConfirmationError)?
                .ok_or(WritableClientError::WriteSendTxError(format!(
                    "Transaction did not receive {} confirmations",
                    self.confirmations,
                )))?;
            self.update_status(WriteTransactionStatus::Confirmed(Box::new(receipt)));
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
    use alloy::primitives::{Address, U256};
    use alloy::sol;
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
