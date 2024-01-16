use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use alloy_primitives::{Address, U256};
use alloy_sol_types::SolCall;
use derive_builder::Builder;
use ethers::middleware::SignerMiddleware;
use ethers::providers::Middleware;
use ethers::signers::Signer;
use ethers::types::TransactionReceipt;
use ethers::utils::hex;
use tracing::info;

#[derive(Builder)]
pub struct WriteContractParameters<C: SolCall + Default> {
    pub call: Option<C>,
    pub address: Option<Address>,
    #[builder(setter(into, strip_option))]
    pub gas: Option<U256>,
    #[builder(setter(into, strip_option))]
    pub gas_price: Option<U256>,
    #[builder(setter(into, strip_option))]
    pub max_fee_per_gas: Option<U256>,
    #[builder(setter(into, strip_option))]
    pub max_priority_fee_per_gas: Option<U256>,
    #[builder(setter(into, strip_option))]
    pub nonce: Option<U256>,
    #[builder(setter(into, strip_option))]
    pub value: Option<U256>,
}

pub struct WritableClient<M: Middleware, S: Signer>(SignerMiddleware<M, S>);

impl<M: Middleware, S: Signer> WritableClient<M, S> {
    // Create a new WriteContract instance, passing a client
    pub fn new(client: SignerMiddleware<M, S>) -> Self {
        Self(client)
    }

    // Executes a write function on a contract.
    pub async fn write<C: SolCall + Default>(
        self,
        parameters: WriteContractParameters<C>,
    ) -> anyhow::Result<TransactionReceipt> {
        let data = parameters
            .call
            .ok_or(anyhow::anyhow!("No call provided"))?
            .abi_encode();

        let transaction_request = AlloyTransactionRequest::new()
            .with_to(parameters.address)
            .with_data(Some(data))
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
