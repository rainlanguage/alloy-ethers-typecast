use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use derive_builder::Builder;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::gas_oracle::GasOracleMiddleware;
use ethers::prelude::gas_oracle::ProviderOracle;
use ethers::prelude::Http;
use ethers::prelude::Provider;
use ethers::providers::{Middleware, PendingTransaction};
use ethers::signers::Signer;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Bytes, TransactionReceipt};
use ethers::utils::hex;
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
    #[error("failed to confirm transaction: {0}")]
    WriteConfirmationError(String),
    #[error("transaction failed")]
    WriteFailedTxError(),
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

pub struct WritableClient<M: Middleware, S: Signer>(
    SignerMiddleware<GasOracleMiddleware<M, ProviderOracle<Provider<Http>>>, S>,
);

impl<M: Middleware, S: Signer> WritableClient<M, S> {
    // Create a new WriteContract instance, passing a client
    pub fn new(
        client: SignerMiddleware<GasOracleMiddleware<M, ProviderOracle<Provider<Http>>>, S>,
    ) -> Self {
        Self(client)
    }

    // Executes a write function on a contract.
    pub async fn write<C: SolCall>(
        &self,
        parameters: WriteContractParameters<C>,
    ) -> Result<TransactionReceipt, WritableClientError> {
        let pending_tx = self.write_pending(parameters).await?;

        info!("Transaction submitted. Awaiting block confirmations...");

        let tx_confirmation = pending_tx
            .confirmations(4)
            .await
            .map_err(|err| WritableClientError::WriteConfirmationError(err.to_string()))?;

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

        let pending_tx = self
            .0
            .send_transaction(ethers_transaction_request, None)
            .await
            .map_err(|err| WritableClientError::WriteSendTxError(err.to_string()))?;

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
