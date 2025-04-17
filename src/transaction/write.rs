use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use alloy::primitives::hex::{decode, FromHexError};
use alloy::primitives::{Address, U256};
use alloy::sol_types::SolCall;
use derive_builder::Builder;
use ethers::middleware::signer::SignerMiddlewareError;
use ethers::middleware::MiddlewareError;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{Middleware, PendingTransaction, ProviderError};
use ethers::signers::Signer;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Bytes, TransactionReceipt};
use ethers::utils::hex;
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
    WriteConfirmationError(ProviderError),
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
    ) -> Result<TransactionReceipt, WritableClientError> {
        let pending_tx = self.write_pending(parameters).await?;

        info!("Transaction submitted. Awaiting block confirmations...");

        let res = pending_tx.confirmations(4).await;

        let tx_confirmation = match res {
            Ok(res) => res,
            Err(provider_err) => {
                let error_to_insert = if let Some(rpc_err) = provider_err.as_error_response() {
                    if rpc_err.is_revert() {
                        match AbiDecodedErrorType::try_from_json_rpc_error(rpc_err.clone()).await {
                            Ok(decoded_err) => {
                                WritableClientError::AbiDecodedErrorType(decoded_err)
                            }
                            Err(decode_failed_err) => {
                                WritableClientError::AbiDecodeFailedErrors(decode_failed_err)
                            }
                        }
                    } else {
                        WritableClientError::RpcError(rpc_err.to_string())
                    }
                } else {
                    WritableClientError::WriteConfirmationError(provider_err)
                };
                return Err(error_to_insert);
            }
        };

        let tx_receipt = match tx_confirmation {
            Some(receipt) => receipt,
            None => return Err(WritableClientError::WriteFailedTxError()),
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
    ) -> Result<ethers::providers::PendingTransaction<'_, M::Provider>, WritableClientError> {
        let transaction_request = AlloyTransactionRequest::new()
            .with_to(Some(parameters.address))
            .with_data(Some(parameters.call.abi_encode()))
            .with_gas(parameters.gas)
            .with_max_fee_per_gas(parameters.max_fee_per_gas)
            .with_max_priority_fee_per_gas(parameters.max_priority_fee_per_gas)
            .with_nonce(parameters.nonce)
            .with_value(parameters.value);

        let ethers_transaction_request = transaction_request.to_eip1559();

        let res = self
            .0
            .send_transaction(ethers_transaction_request, None)
            .await;

        let pending_tx = if let Err(err) = res {
            if let SignerMiddlewareError::MiddlewareError(err) = err {
                if let Some(rpc_err) = err.as_error_response() {
                    match rpc_err.data.clone() {
                        Some(data) => {
                            let data = data.as_str().unwrap();
                            let data_slice = decode(data)?;
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
                }
                return Err(WritableClientError::WriteSendTxError(err.to_string()));
            } else {
                return Err(WritableClientError::WriteSendTxError(err.to_string()));
            }
        } else {
            res.map_err(|e| WritableClientError::WriteSendTxError(e.to_string()))?
        };

        Ok(pending_tx)
    }

    pub async fn prepare_request<C: SolCall>(
        &self,
        parameters: WriteContractParameters<C>,
    ) -> Result<TypedTransaction, WritableClientError> {
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
        self.0
            .fill_transaction(&mut tx, None)
            .await
            .map_err(|e| WritableClientError::WriteFillTxError(e.to_string()))?;

        Ok(tx)
    }

    pub async fn sign_request(&self, tx: TypedTransaction) -> Result<Bytes, WritableClientError> {
        let signature = self
            .0
            .sign_transaction(&tx, self.0.signer().address())
            .await
            .map_err(|e| WritableClientError::WriteSignTxError(e.to_string()))?;

        Ok(tx.rlp_signed(&signature))
    }

    pub async fn send_request(
        &self,
        bytes: Bytes,
    ) -> Result<PendingTransaction<'_, M::Provider>, WritableClientError> {
        self.0
            .send_raw_transaction(bytes)
            .await
            .map_err(|e| WritableClientError::WriteSendTxError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::mock_middleware::{MockJsonRpcClient, MockMiddleware};
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
