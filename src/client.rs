use crate::ethers_address_to_alloy;
use crate::gas_fee_middleware::{GasFeeMiddleware, GasFeeMiddlewareError, GasFeeSpeed};
use alloy_primitives::Address;
use ethers::middleware::SignerMiddleware;
use ethers::prelude::{Http, Provider};
use ethers::signers::{HDPath, Ledger, LedgerError};
use std::iter::zip;
use thiserror::Error;
use std::ops::Range;

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

pub enum DerivationPathType {
    LedgerLive,
    Legacy,
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

    /// List all addresses derived from a range of derivation indexes for a given derivation path type
    pub async fn list_derivation_addresses(
        chain_id: u64,
        derivation_path_type: DerivationPathType,
        index_range: Range<usize>,
    ) -> Result<Vec<(Address, usize)>, LedgerClientError> {
        let wallet = Self::init_ledger(None, chain_id).await?;

        // Prepare list of derivation paths for given indexes & type
        let derivations: Vec<HDPath> = match derivation_path_type {
            DerivationPathType::LedgerLive => index_range.clone()
                .map(HDPath::LedgerLive)
                .collect(),
            DerivationPathType::Legacy => index_range.clone()
                .map(HDPath::Legacy)
                .collect(),
        };

        // Get address for each derivation index
        let mut all_addresses: Vec<Address> = vec![];
        for derivation in derivations {
            let address = wallet.get_address_with_path(&derivation).await?;
            all_addresses.push(ethers_address_to_alloy(address));
        }

        // Zip lists of addresses & indexes
        let all_indexes: Vec<usize> = index_range.collect();
        Ok(zip(all_addresses, all_indexes).collect())
    }
}
