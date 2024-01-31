use ethers::middleware::{SignerMiddleware, gas_oracle::GasOracleMiddleware};
use ethers::prelude::{Http, Provider, gas_oracle::ProviderOracle, signer::SignerMiddlewareError};
use ethers::signers::{HDPath, Ledger, LedgerError};
use url::ParseError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LedgerClientError {
    #[error(transparent)]
    LedgerError(#[from] LedgerError),
    #[error(transparent)]
    UrlParserError(#[from] ParseError),
    #[error(transparent)]
    SignerMiddlewareError(#[from] SignerMiddlewareError<Provider<Http>, Ledger>),
}

pub struct LedgerClient {
    pub client: GasOracleMiddleware<SignerMiddleware<Provider<Http>, Ledger>, ProviderOracle<Provider<Http>>>,
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
        .await?;
        let provider = Provider::<Http>::try_from(rpc_url.clone())?;
        let signer = SignerMiddleware::new_with_provider_chain(provider.clone(), wallet)
            .await?;
        let client = GasOracleMiddleware::new(signer, ProviderOracle::new(provider));
        Ok(Self { client })
    }
}
