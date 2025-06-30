use alloy::hex;
use alloy::network::{AnyNetwork, AnyReceiptEnvelope, TransactionBuilder};
use alloy::primitives::hex::{decode, FromHexError};
use alloy::primitives::{Address, U256};
use alloy::providers::{
    PendingTransactionBuilder, PendingTransactionError, Provider, WalletProvider,
};
use alloy::rpc::types::{TransactionReceipt, TransactionRequest};
use alloy::serde::WithOtherFields;
use alloy::sol_types::SolCall;
use alloy::transports::RpcError;
use derive_builder::Builder;
use rain_error_decoding::{AbiDecodeFailedErrors, AbiDecodedErrorType};
use thiserror::Error;
use tracing::info;

#[derive(Error, Debug)]
pub enum WritableClientError {
    #[error("failed to fill transaction: {0}")]
    WriteFillTxError(String),
    #[error("failed to sign transaction: {0}")]
    WriteSignTxError(String),
    #[error("failed to send transaction: {0}")]
    WriteSendTxError(String),
    #[error(transparent)]
    WriteConfirmationError(PendingTransactionError),
    #[error("transaction failed")]
    WriteFailedTxError(),
    #[error(transparent)]
    AbiDecodeFailedErrors(#[from] AbiDecodeFailedErrors),
    #[error(transparent)]
    AbiDecodedErrorType(#[from] AbiDecodedErrorType),
    #[error(transparent)]
    HexDecodeError(#[from] FromHexError),
    #[error("rpc provider returned an error: '{0}'")]
    RpcError(String),
}

#[derive(Builder, Clone, Debug)]
pub struct WriteContractParameters<C: SolCall> {
    pub call: C,
    pub address: Address,
    #[builder(setter(into), default)]
    pub gas: Option<u64>,
    #[builder(setter(into), default)]
    pub gas_price: Option<U256>,
    #[builder(setter(into), default)]
    pub max_fee_per_gas: Option<u128>,
    #[builder(setter(into), default)]
    pub max_priority_fee_per_gas: Option<u128>,
    #[builder(setter(into), default)]
    pub nonce: Option<u64>,
    #[builder(setter(into), default)]
    pub value: Option<U256>,
}

impl<C: SolCall> WriteContractParameters<C> {
    pub fn build_transaction_request(&self) -> TransactionRequest {
        let mut tx_request = TransactionRequest::default()
            .with_to(self.address)
            .with_input(self.call.abi_encode());

        if let Some(gas) = self.gas {
            tx_request = tx_request.with_gas_limit(gas);
        }
        if let Some(max_fee_per_gas) = self.max_fee_per_gas {
            tx_request = tx_request.with_max_fee_per_gas(max_fee_per_gas);
        }
        if let Some(max_priority_fee_per_gas) = self.max_priority_fee_per_gas {
            tx_request = tx_request.with_max_priority_fee_per_gas(max_priority_fee_per_gas);
        }
        if let Some(nonce) = self.nonce {
            tx_request = tx_request.with_nonce(nonce);
        }
        if let Some(value) = self.value {
            tx_request = tx_request.with_value(value);
        }
        tx_request
    }
}

#[derive(Clone)]
pub struct WritableClient<P: Provider<AnyNetwork> + WalletProvider<AnyNetwork> + Clone>(P);

impl<P: Provider<AnyNetwork> + WalletProvider<AnyNetwork> + Clone> WritableClient<P> {
    pub fn new(client: P) -> Self {
        Self(client)
    }

    // Executes a write function on a contract.
    pub async fn write<C: SolCall>(
        &self,
        parameters: WriteContractParameters<C>,
    ) -> Result<TransactionReceipt<AnyReceiptEnvelope<alloy::rpc::types::Log>>, WritableClientError>
    {
        let pending_tx = self.write_pending(parameters, 4).await?;

        info!("Transaction submitted. Awaiting block confirmations...");

        let res = pending_tx.get_receipt().await;

        let receipt = match res {
            Ok(receipt) => receipt,
            Err(PendingTransactionError::TransportError(RpcError::ErrorResp(err_payload))) => {
                return Err(
                    match AbiDecodedErrorType::try_from_json_rpc_error(err_payload).await {
                        Ok(decoded_err) => WritableClientError::AbiDecodedErrorType(decoded_err),
                        Err(decode_failed_err) => {
                            WritableClientError::AbiDecodeFailedErrors(decode_failed_err)
                        }
                    },
                );
            }
            Err(provider_err) => {
                return Err(WritableClientError::WriteConfirmationError(provider_err));
            }
        };

        info!("Transaction Confirmed");
        info!("✅ Hash : 0x{}", hex::encode(receipt.transaction_hash));
        Ok(receipt.inner)
    }

    // Executes a write function but returns a PendingTransaction instance
    pub async fn write_pending<C: SolCall>(
        &self,
        parameters: WriteContractParameters<C>,
        confirmations: u64,
    ) -> Result<PendingTransactionBuilder<AnyNetwork>, WritableClientError> {
        let transaction_request = parameters.build_transaction_request();

        let res = self
            .0
            .send_transaction(WithOtherFields::new(transaction_request))
            .await;

        let pending_tx = if let Err(err) = res {
            if let RpcError::ErrorResp(err) = err {
                match err.data.clone() {
                    Some(data) => {
                        let data_slice = decode(data.get())?;
                        let err = AbiDecodedErrorType::selector_registry_abi_decode(
                            data_slice.as_slice(),
                        )
                        .await?;
                        return Err(WritableClientError::WriteSendTxError(err.to_string()));
                    }
                    None => {
                        return Err(WritableClientError::WriteSendTxError(err.to_string()));
                    }
                }
            } else {
                return Err(WritableClientError::WriteSendTxError(err.to_string()));
            }
        } else {
            res.map_err(|e| WritableClientError::WriteSendTxError(e.to_string()))?
        };

        Ok(pending_tx.with_required_confirmations(confirmations))
    }

    pub async fn send_request(
        &self,
        tx: TransactionRequest,
    ) -> Result<PendingTransactionBuilder<AnyNetwork>, WritableClientError> {
        self.0
            .send_transaction(WithOtherFields::new(tx))
            .await
            .map_err(|e| WritableClientError::WriteSendTxError(e.to_string()))
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
            .gas(100000)
            .gas_price(U256::from(100000))
            .max_fee_per_gas(100000)
            .max_priority_fee_per_gas(100000)
            .nonce(100000)
            .value(U256::from(100000))
            .build()?;

        assert_eq!(parameters.address, Address::repeat_byte(0x11));
        assert_eq!(parameters.call.a, U256::from(42));
        assert_eq!(parameters.call.b, U256::from(10));

        Ok(())
    }

    #[tokio::test]
    async fn test_write() {
        let asserter = Asserter::new();
        let wallet = LocalSigner::random();

        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .network::<AnyNetwork>()
            .connect_mocked_client(asserter.clone());

        // Create a WriteContractParameters instance
        let parameters = WriteContractParametersBuilder::default()
            .call(fooCall {
                a: U256::from(42), // these could be anything, the mock provider doesn't care
                b: U256::from(10),
            })
            .address(Address::repeat_byte(0x22))
            .build()
            .unwrap();

        // eth_estimateGas response
        asserter.push_success(&"0x5208");

        // eth_feeHistory response
        asserter.push_success(&json!({
          "oldestBlock": "0x1554ec2",
          "reward": [
            [ "0x4b571c0", "0x2f23c46c" ],
            [ "0x396c1b9", "0x4d579d50" ],
            [ "0x77359400", "0x77359400" ],
            [ "0x2faf080", "0x3b9aca00" ]
          ],
          "baseFeePerGas": [ "0x3af6c9f1", "0x3b19496d", "0x36647614", "0x302c838b", "0x359f85b3" ],
          "gasUsedRatio": [ 0.5091416944444445, 0.18145872222222223, 0.04269041059401201, 0.9524652037856148 ],
          "baseFeePerBlobGas": [ "0x320b8540d", "0x384cf5f4e", "0x3f5694c1f", "0x44831ac79", "0x3f5694c1f" ],
          "blobGasUsedRatio": [ 1, 1, 0.8333333333333334, 0.16666666666666666 ]
        }));

        // eth_getTransactionCount response, nonce
        asserter.push_success(&"0x123");

        // eth_chainId response, chain id
        asserter.push_success(&"0x1");

        // eth_sendRawTransaction response, transaction hash
        asserter
            .push_success(&"0x0000000000000000000000000000000000000000000000000000000000000001");

        // mock eth_getTransactionReceipt response, json transaction receipt
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
        asserter.push_success(&mock_receipt);
        asserter.push_success(&mock_receipt);

        // Create a WritableClient instance with the mock client
        let writable_client = WritableClient::new(provider);

        // Call the write method
        let _ = writable_client.write(parameters).await.unwrap();
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
