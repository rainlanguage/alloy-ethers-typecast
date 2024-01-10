use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use ethers::middleware::SignerMiddleware;
use ethers::providers::Middleware;
use ethers::signers::Signer;
use ethers::types::{Eip1559TransactionRequest, TransactionReceipt};
use ethers::utils::hex;
use tracing::info;

pub struct ExecutableTransaction<M: Middleware, S: Signer> {
    pub transaction_request: Eip1559TransactionRequest,
    pub client: SignerMiddleware<M, S>,
}

impl<M: Middleware, S: Signer> ExecutableTransaction<M, S> {
    pub async fn from_alloy_transaction_request(
        transaction_request: AlloyTransactionRequest,
        client: SignerMiddleware<M, S>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            transaction_request: transaction_request.to_eip1559(),
            client,
        })
    }

    pub async fn from_ethers_transaction_request(
        transaction_request: Eip1559TransactionRequest,
        client: SignerMiddleware<M, S>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            transaction_request: transaction_request,
            client,
        })
    }

    // Execute the transaction
    pub async fn execute(&self) -> anyhow::Result<TransactionReceipt> {
        let pending_tx = self
            .client
            .send_transaction(self.transaction_request.clone(), None)
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
