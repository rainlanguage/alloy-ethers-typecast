use ethers::middleware::SignerMiddleware;
use ethers::prelude::{Http, Provider};
use ethers_signers::{HDPath, Ledger};

pub struct LedgerClient {
    client: SignerMiddleware<Provider<Http>, Ledger>,
}

impl LedgerClient {
    pub async fn new(
        ledger_derivation_path: Option<usize>,
        chain_id: u64,
        rpc_url: String,
    ) -> anyhow::Result<Self> {
        let wallet = Ledger::new(
            HDPath::LedgerLive(ledger_derivation_path.unwrap_or(0)),
            chain_id,
        )
        .await?;
        let provider = Provider::<Http>::try_from(rpc_url.clone())?;
        let client = SignerMiddleware::new_with_provider_chain(provider, wallet).await?;
        Ok(Self { client })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::middleware::Middleware;
    use ethers_signers::Signer;

    #[tokio::test]
    async fn test_new_ledger_client() {
        let chain_id = 1;
        let rpc_url = "https://example.com".to_string();

        let ledger_client = LedgerClient::new(None, chain_id, rpc_url.clone()).await;
        assert!(ledger_client.is_ok());

        let ledger_client = ledger_client.unwrap();
        assert_eq!(
            ledger_client.client.provider().url().as_str(),
            rpc_url.as_str()
        );
        assert_eq!(ledger_client.client.signer().chain_id(), chain_id);
    }
}
