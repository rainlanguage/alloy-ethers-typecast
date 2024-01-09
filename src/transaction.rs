use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use ethers::providers::Middleware;
use ethers::providers::Provider;
use ethers::types::{Address, U256};
use ethers::types::{Eip1559TransactionRequest, TransactionReceipt};
use ethers::utils::hex;
use ethers::utils::Ganache;
use log::info;
use std::convert::TryFrom;

struct ExecutableTransaction<M: Middleware> {
    transaction_request: Eip1559TransactionRequest,
    client: M,
}

impl<M: Middleware> ExecutableTransaction<M> {
    pub async fn from_alloy_transaction_request(
        transaction_request: AlloyTransactionRequest,
        client: M,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            transaction_request: transaction_request.to_eip1559(),
            client,
        })
    }

    pub async fn from_ethers_transaction_request(
        transaction_request: Eip1559TransactionRequest,
        client: M,
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
