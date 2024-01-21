use ethers::middleware::SignerMiddleware;
use ethers::prelude::{Http, Provider};
use ethers::signers::{HDPath, Ledger};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum LedgerClientError {
    #[error("failed to instantiate provider: {0}")]
    CreateLedgerClientProviderError(String),
    #[error("failed to instantiate Ledger device: {0}")]
    CreateLedgerClientDeviceError(String),
    #[error("failed to instantiate Ledger middleware: {0}")]
    CreateLedgerClientMiddlewareError(String),
}

pub struct LedgerClient {
    pub client: SignerMiddleware<Provider<Http>, Ledger>,
}

impl LedgerClient {
    pub async fn new(
        ledger_derivation_path: Option<usize>,
        chain_id: u64,
        rpc_url: String,
    ) -> Result<Self, LedgerClientError> {
        let wallet = Ledger::new(
            HDPath::LedgerLive(ledger_derivation_path.unwrap_or(0)),
            chain_id,
        )
        .await
        .map_err(|err| LedgerClientError::CreateLedgerClientDeviceError(err.to_string()))?;
        let provider = Provider::<Http>::try_from(rpc_url.clone())
            .map_err(|err| LedgerClientError::CreateLedgerClientProviderError(err.to_string()))?;
        let client = SignerMiddleware::new_with_provider_chain(provider, wallet)
            .await
            .map_err(|err| LedgerClientError::CreateLedgerClientMiddlewareError(err.to_string()))?;
        Ok(Self { client })
    }
}
