use ethers::middleware::{gas_oracle::GasOracleMiddleware, SignerMiddleware};
use ethers::prelude::{gas_oracle::ProviderOracle, signer::SignerMiddlewareError, Http, Provider};
use ethers::signers::{HDPath, Ledger, LedgerError};
use thiserror::Error;
use url::ParseError;

#[derive(Error, Debug)]
pub enum LedgerClientError {
    #[error(transparent)]
    LedgerError(#[from] LedgerError),
    #[error(transparent)]
    UrlParserError(#[from] ParseError),
    #[error(transparent)]
    SignerMiddlewareError(
        #[from]
        SignerMiddlewareError<
            GasOracleMiddleware<Provider<Http>, ProviderOracle<Provider<Http>>>,
            Ledger,
        >,
    ),
}

pub struct LedgerClient {
    pub client: SignerMiddleware<
        GasOracleMiddleware<Provider<Http>, ProviderOracle<Provider<Http>>>,
        Ledger,
    >,
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
        let gas_oracle_middleware =
            GasOracleMiddleware::new(provider.clone(), ProviderOracle::new(provider));
        let client = SignerMiddleware::<
            GasOracleMiddleware<Provider<Http>, ProviderOracle<Provider<Http>>>,
            Ledger,
        >::new_with_provider_chain(gas_oracle_middleware, wallet)
        .await?;
        Ok(Self { client })
    }
}
