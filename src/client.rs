use crate::transaction::{GasFeeMiddleware, GasFeeMiddlewareError, GasFeeSpeed};
use ethers::middleware::SignerMiddleware;
use ethers::prelude::{signer::SignerMiddlewareError, Http, Provider};
use ethers::signers::{HDPath, Ledger, LedgerError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LedgerClientError {
    #[error(transparent)]
    URLParserError(#[from] url::ParseError),
    #[error(transparent)]
    LedgerError(#[from] LedgerError),
    #[error(transparent)]
    SignerMiddlewareError(#[from] SignerMiddlewareError<GasFeeMiddleware<Provider<Http>>, Ledger>),
    #[error(transparent)]
    GasFeeMiddlewareError(#[from] GasFeeMiddlewareError<Provider<Http>>),
}

pub struct LedgerClient {
    pub client: SignerMiddleware<GasFeeMiddleware<Provider<Http>>, Ledger>,
}

impl LedgerClient {
    pub async fn new(
        ledger_derivation_path: Option<usize>,
        chain_id: u64,
        rpc_url: String,
        gas_fee_speed: GasFeeSpeed,
    ) -> Result<Self, LedgerClientError> {
        let wallet = Ledger::new(
            HDPath::LedgerLive(ledger_derivation_path.unwrap_or(0)),
            chain_id,
        )
        .await?;
        let provider = Provider::<Http>::try_from(rpc_url.clone())?;
        let gas_fee_middleware = GasFeeMiddleware::new(provider, gas_fee_speed)?;
        let client = SignerMiddleware::new_with_provider_chain(gas_fee_middleware, wallet).await?;

        Ok(Self { client })
    }
}
