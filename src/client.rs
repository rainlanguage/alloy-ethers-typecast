use ethers::middleware::SignerMiddleware;
use ethers::prelude::{Http, Provider};
use ethers_signers::{HDPath, Ledger};

pub struct LedgerClientConfig {
    pub ledger_derivation_path: Option<usize>,
    pub chain_id: u64,
    pub rpc_url: String,
}

pub struct LedgerClient {
    pub client: SignerMiddleware<Provider<Http>, Ledger>,
}

impl LedgerClient {
    pub async fn new(config: LedgerClientConfig) -> anyhow::Result<Self> {
        let wallet = Ledger::new(
            HDPath::LedgerLive(config.ledger_derivation_path.unwrap_or(0)),
            config.chain_id,
        )
        .await?;
        let provider = Provider::<Http>::try_from(config.rpc_url.clone())?;
        let client = SignerMiddleware::new_with_provider_chain(provider, wallet).await?;
        Ok(Self { client })
    }
}
