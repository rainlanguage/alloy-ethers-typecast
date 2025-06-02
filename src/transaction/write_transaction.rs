use crate::transaction::{WritableClient, WritableClientError, WriteContractParameters};
use alloy::network::{AnyNetwork, AnyReceiptEnvelope};
use alloy::providers::Provider;
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::sol_types::SolCall;

#[derive(Clone, Debug)]
pub enum WriteTransactionStatus<C: SolCall> {
    PendingPrepare(Box<WriteContractParameters<C>>),
    PendingSignAndSend(Box<TransactionRequest>),
    Confirmed(Box<TransactionReceipt<AnyReceiptEnvelope<alloy::rpc::types::Log>>>),
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
    WriteTransaction<P, C, F>
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
        self.sign_and_send().await?;
        Ok(())
    }

    async fn prepare(&mut self) -> Result<(), WritableClientError> {
        if let WriteTransactionStatus::PendingPrepare(parameters) = &self.status {
            let tx_request = parameters.build_transaction_request();
            self.update_status(WriteTransactionStatus::PendingSignAndSend(Box::new(
                tx_request,
            )));
        }
        Ok(())
    }

    async fn sign_and_send(&mut self) -> Result<(), WritableClientError> {
        if let WriteTransactionStatus::PendingSignAndSend(tx_request) = &self.status {
            let pending_tx = self.client.send_request(*tx_request.to_owned()).await?;
            let receipt = pending_tx
                .with_required_confirmations(self.confirmations.into())
                .get_receipt()
                .await
                .map_err(WritableClientError::WriteConfirmationError)?;
            if !receipt.inner.inner.status() {
                return Err(WritableClientError::WriteFailedTxError());
            }
            self.update_status(WriteTransactionStatus::Confirmed(Box::new(receipt.inner)));
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
    use super::*;
    use alloy::primitives::{Address, U256};
    use alloy::providers::mock::Asserter;
    use alloy::providers::ProviderBuilder;
    use alloy::signers::local::LocalSigner;
    use alloy::sol;
    use serde_json::json;
    use tracing_subscriber;
    use tracing_subscriber::FmtSubscriber;

    sol! {
       function foo(uint256 a, uint256 b) external view returns (Foo);

        struct Foo {
            uint256 bar;
            address baz;
        }
    }

    // Helper function to create test parameters
    fn create_test_parameters() -> WriteContractParameters<fooCall> {
        WriteContractParameters {
            call: fooCall {
                a: U256::from(42),
                b: U256::from(10),
            },
            address: Address::repeat_byte(0x22),
            gas: Some(123),
            gas_price: Some(U256::from(100)),
            max_fee_per_gas: Some(100),
            max_priority_fee_per_gas: Some(100),
            nonce: Some(1),
            value: Some(U256::from(100)),
        }
    }

    // Helper function to create a mock provider
    fn create_mock_provider(asserter: Asserter) -> impl Provider<AnyNetwork> + Clone {
        let wallet = LocalSigner::random();
        ProviderBuilder::new()
            .wallet(wallet)
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter)
    }

    #[tokio::test]
    async fn test_write_transaction() {
        let asserter = Asserter::new();
        let provider = create_mock_provider(asserter.clone());

        // eth_chainId response
        asserter.push_success(&"0x1");

        // eth_sendRawTransaction response
        asserter
            .push_success(&"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        // mock eth_getTransactionReceipt response
        let mock_receipt = json!({
            "blockHash": "0xa957d47df264a31badc3ae823e10ac1d444b098d9b73d204c40426e57f47e8c3",
            "blockNumber": "0xeff35f",
            "contractAddress": null,
            "cumulativeGasUsed": "0xa12515",
            "effectiveGasPrice": "0x5a9c688d4",
            "from": "0x6221a03dae12247eb398fd867784cacfdcfff4e7",
            "gasUsed": "0xb4c8",
            "logs": [],
            "logsBloom": "0x".to_owned() + &"0".repeat(512),
            "status": "0x1",
            "to": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "transactionHash": "0x85d995eba9763907fdf35cd2034144dd9d53ce32cbec21349d4b12823c6860c5",
            "transactionIndex": "0x66",
            "type": "0x2"
        });
        asserter.push_success(&mock_receipt);
        asserter.push_success(&mock_receipt);

        WriteTransaction::new(provider, create_test_parameters(), 1, |_| {})
            .execute()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_transaction_failure() {
        let asserter = Asserter::new();
        let provider = create_mock_provider(asserter.clone());

        // eth_chainId response
        asserter.push_success(&"0x1");

        // eth_sendRawTransaction response
        asserter
            .push_success(&"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        // mock eth_getTransactionReceipt response with status = 0 (failure)
        let mock_receipt = json!({
            "blockHash": "0xa957d47df264a31badc3ae823e10ac1d444b098d9b73d204c40426e57f47e8c3",
            "blockNumber": "0xeff35f",
            "contractAddress": null,
            "cumulativeGasUsed": "0xa12515",
            "effectiveGasPrice": "0x5a9c688d4",
            "from": "0x6221a03dae12247eb398fd867784cacfdcfff4e7",
            "gasUsed": "0xb4c8",
            "logs": [],
            "logsBloom": "0x".to_owned() + &"0".repeat(512),
            "status": "0x0", // Transaction failed
            "to": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "transactionHash": "0x85d995eba9763907fdf35cd2034144dd9d53ce32cbec21349d4b12823c6860c5",
            "transactionIndex": "0x66",
            "type": "0x2"
        });
        asserter.push_success(&mock_receipt);
        asserter.push_success(&mock_receipt);

        let result = WriteTransaction::new(provider, create_test_parameters(), 1, |_| {})
            .execute()
            .await;
        assert!(matches!(
            result,
            Err(WritableClientError::WriteFailedTxError())
        ));
    }

    #[tokio::test]
    async fn test_network_error_during_send() {
        let asserter = Asserter::new();
        let provider = create_mock_provider(asserter.clone());

        // eth_chainId response
        asserter.push_success(&"0x1");

        // Simulate network error during eth_sendRawTransaction
        asserter.push_failure_msg("network error during transaction send");

        let result = WriteTransaction::new(provider, create_test_parameters(), 1, |_| {})
            .execute()
            .await;
        assert!(matches!(
            result,
            Err(WritableClientError::WriteSendTxError(msg)) if msg.contains("network error during transaction send")
        ));
    }

    #[tokio::test]
    async fn test_network_error_during_confirmation() {
        let asserter = Asserter::new();
        let provider = create_mock_provider(asserter.clone());

        // eth_chainId response
        asserter.push_success(&"0x1");

        // eth_sendRawTransaction response
        asserter
            .push_success(&"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        // Simulate network error during receipt confirmation
        asserter.push_failure_msg("network error during receipt confirmation");

        let result = WriteTransaction::new(provider, create_test_parameters(), 1, |_| {})
            .execute()
            .await;
        assert!(matches!(
            result,
            Err(WritableClientError::WriteConfirmationError(_))
        ));
    }

    #[tokio::test]
    async fn test_invalid_receipt_data() {
        let asserter = Asserter::new();
        let provider = create_mock_provider(asserter.clone());

        // eth_chainId response
        asserter.push_success(&"0x1");

        // eth_sendRawTransaction response
        asserter
            .push_success(&"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        // Push invalid receipt data
        asserter.push_success(&"invalid_json");

        let result = WriteTransaction::new(provider, create_test_parameters(), 1, |_| {})
            .execute()
            .await;
        assert!(matches!(
            result,
            Err(WritableClientError::WriteConfirmationError(_))
        ));
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
