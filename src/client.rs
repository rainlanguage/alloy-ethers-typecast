use ethers::middleware::SignerMiddleware;
use ethers::prelude::{Http, Provider};
use ethers_signers::{HDPath, Ledger};

pub struct LedgerClient {
    pub client: SignerMiddleware<Provider<Http>, Ledger>,
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
