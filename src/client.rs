use crate::ethers_address_to_alloy;
use crate::gas_fee_middleware::{GasFeeMiddleware, GasFeeMiddlewareError, GasFeeSpeed};
use alloy_primitives::Address;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::{Http, Provider};
use ethers::signers::{Ledger, LedgerError};


use thiserror::Error;

pub use ethers::signers::HDPath;

#[derive(Error, Debug)]
pub enum LedgerClientError {
    #[error("failed to instantiate provider: {0}")]
    CreateLedgerClientProviderError(String),
    #[error("failed to instantiate Ledger device: {0}")]
    CreateLedgerClientDeviceError(String),
    #[error("failed to instantiate Ledger middleware: {0}")]
    CreateLedgerClientMiddlewareError(String),
    #[error(transparent)]
    GasFeeMiddlewareError(#[from] GasFeeMiddlewareError<Provider<Http>>),
    #[error(transparent)]
    LedgerError(#[from] LedgerError),
}

pub struct LedgerClient {
    pub client: SignerMiddleware<GasFeeMiddleware<Provider<Http>>, Ledger>,
}

impl LedgerClient {
    /// Initialize a new Ledger connection
    async fn init_ledger(
        derivation: Option<HDPath>,
        chain_id: u64,
    ) -> Result<Ledger, LedgerClientError> {
        Ok(Ledger::new(derivation.unwrap_or(HDPath::LedgerLive(0)), chain_id).await?)
    }

    /// Initialize a new Ledger Signer with all desired middleware
    pub async fn new(
        derivation: Option<HDPath>,
        chain_id: u64,
        rpc_url: String,
        gas_fee_speed: Option<GasFeeSpeed>,
    ) -> Result<Self, LedgerClientError> {
        let wallet = Self::init_ledger(derivation, chain_id).await?;
        let provider = Provider::<Http>::try_from(rpc_url.clone())
            .map_err(|err| LedgerClientError::CreateLedgerClientProviderError(err.to_string()))?;
        let gas_fee_middleware = GasFeeMiddleware::new(provider, gas_fee_speed)?;
        let client = SignerMiddleware::new_with_provider_chain(gas_fee_middleware, wallet)
            .await
            .map_err(|err| LedgerClientError::CreateLedgerClientMiddlewareError(err.to_string()))?;
        Ok(Self { client })
    }

    /// Get an addresses derived a derivation path
    pub async fn get_derivation_address(
        chain_id: u64,
        derivation: HDPath,
    ) -> Result<Address, LedgerClientError> {
        let wallet = Self::init_ledger(None, chain_id).await?;
        let address = wallet.get_address_with_path(&derivation).await?;
        let address_alloy = ethers_address_to_alloy(address);
        Ok(address_alloy)
    }
}
