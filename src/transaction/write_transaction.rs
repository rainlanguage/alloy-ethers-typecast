use crate::transaction::{WritableClient, WritableClientError, WriteContractParameters};
use alloy::network::{AnyNetwork, AnyReceiptEnvelope};
use alloy::providers::Provider;
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::sol_types::SolCall;

// const TRANSACTION_RETRY_INTERVAL_SECONDS: u64 = 5;
// const TRANSACTION_RETRY_COUNT: usize = 15;

#[derive(Clone, Debug)]
pub enum WriteTransactionStatus<C: SolCall> {
    PendingPrepare(Box<WriteContractParameters<C>>),
    PendingSignAndSend(TransactionRequest),
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
            self.update_status(WriteTransactionStatus::PendingSignAndSend(tx_request));
        }
        Ok(())
    }

    async fn sign_and_send(&mut self) -> Result<(), WritableClientError> {
        if let WriteTransactionStatus::PendingSignAndSend(tx_request) = &self.status {
            let pending_tx = self.client.send_request(tx_request.to_owned()).await?;
            let receipt = pending_tx
                // NOTE: retries are built-in but configured at the provider level
                .with_required_confirmations(self.confirmations.into())
                .get_receipt()
                .await
                .map_err(WritableClientError::WriteConfirmationError)?;
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
    use crate::transaction::WriteContractParametersBuilder;

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

    #[tokio::test]
    async fn test_write_transaction() {
        let asserter = Asserter::new();
        let wallet = LocalSigner::random();

        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());

        // Create a WriteContractParameters instance
        let parameters = WriteContractParameters {
            call: fooCall {
                a: U256::from(42), // these could be anything, the mock provider doesn't care
                b: U256::from(10),
            },
            address: Address::repeat_byte(0x22),
            gas: Some(123),
            gas_price: Some(U256::from(100)),
            max_fee_per_gas: Some(100),
            max_priority_fee_per_gas: Some(100),
            nonce: Some(1),
            value: Some(U256::from(100)),
        };

        // Create a mock response for the transaction hash
        let mock_tx_hash = "0x0000000000000000000000000000000000000000000000000000000000000001";
        asserter.push_success(&mock_tx_hash);
        asserter.push_success(&mock_tx_hash.clone());

        // let mock_fee_history = json!({
        //   "oldestBlock": "0x1554ec2",
        //   "reward": [
        //     [ "0x4b571c0", "0x2f23c46c" ],
        //     [ "0x396c1b9", "0x4d579d50" ],
        //     [ "0x77359400", "0x77359400" ],
        //     [ "0x2faf080", "0x3b9aca00" ]
        //   ],
        //   "baseFeePerGas": [ "0x3af6c9f1", "0x3b19496d", "0x36647614", "0x302c838b", "0x359f85b3" ],
        //   "gasUsedRatio": [ 0.5091416944444445, 0.18145872222222223, 0.04269041059401201, 0.9524652037856148 ],
        //   "baseFeePerBlobGas": [ "0x320b8540d", "0x384cf5f4e", "0x3f5694c1f", "0x44831ac79", "0x3f5694c1f" ],
        //   "blobGasUsedRatio": [ 1, 1, 0.8333333333333334, 0.16666666666666666 ]
        // });
        // asserter.push_success(&mock_fee_history);

        // // Create a mock response for eth_getTransactionCount (nonce)
        // let mock_nonce = "0x1";
        // asserter.push_success(&mock_nonce);

        // Create a mock response for the transaction receipt
        let mock_receipt = json!({
            "blockHash": "0xa957d47df264a31badc3ae823e10ac1d444b098d9b73d204c40426e57f47e8c3",
            "blockNumber": "0xeff35f",
            "contractAddress": null,
            "cumulativeGasUsed": "0xa12515",
            "effectiveGasPrice": "0x5a9c688d4",
            "from": "0x6221a03dae12247eb398fd867784cacfdcfff4e7",
            "gasUsed": "0xb4c8",
            "logs": [],
            "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000080000000000000000200000000000000000000020000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020001000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000010200000000000000000000000000000000000000000000000000000020000",
            "status": "0x1",
            "to": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
            "transactionHash": "0x85d995eba9763907fdf35cd2034144dd9d53ce32cbec21349d4b12823c6860c5",
            "transactionIndex": "0x66",
            "type": "0x2"
        });
        asserter.push_success(&mock_receipt);

        WriteTransaction::new(provider, parameters, 1, |_| {})
            .execute()
            .await
            .unwrap();
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
