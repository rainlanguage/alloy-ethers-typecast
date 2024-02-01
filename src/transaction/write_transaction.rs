use alloy_sol_types::SolCall;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::{
    gas_oracle::GasOracleMiddleware, gas_oracle::ProviderOracle, Http, Provider,
};
use ethers::providers::Middleware;
use ethers::signers::Signer;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Bytes, TransactionReceipt};

use crate::transaction::{WritableClient, WritableClientError, WriteContractParameters};

#[derive(Clone, Debug)]
pub enum WriteTransactionStatus<C: SolCall> {
    PendingPrepare(Box<WriteContractParameters<C>>),
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
        client: SignerMiddleware<GasOracleMiddleware<M, ProviderOracle<Provider<Http>>>, S>,
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
            let tx_request = self.client.prepare_request(*parameters.clone()).await?;
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