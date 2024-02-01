use crate::utils::eip1559_fee_estimator;
use async_trait::async_trait;
use ethers::core::types::{transaction::eip2718::TypedTransaction, BlockId};
use ethers::core::utils::format_units;
use ethers::providers::{Middleware, MiddlewareError, ProviderError};
use ethers::types::BlockNumber;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::info;

const EIP1559_FEE_ESTIMATION_PAST_BLOCKS: i32 = 3;
const EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_SLOW: f64 = 25.0;
const EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_MEDIUM: f64 = 50.0;
const EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_FAST: f64 = 75.0;
const EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_FASTEST: f64 = 90.0;

const EIP1559_FEE_ESTIMATION_REWARD_PERCENTILES: [f64; 4] = [
    EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_SLOW,
    EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_MEDIUM,
    EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_FAST,
    EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_FASTEST,
];

#[derive(Serialize, Deserialize, Debug, Clone)]
#[repr(u8)]
pub enum GasFeeSpeed {
    Slow,
    Medium,
    Fast,
    Fastest,
}

const DEFAULT_GAS_FEE_SPEED: GasFeeSpeed = GasFeeSpeed::Medium;

#[derive(Debug)]
pub struct GasFeeMiddleware<M> {
    inner: M,
    gas_fee_speed: Option<GasFeeSpeed>,
}

#[derive(Error, Debug)]
pub enum GasFeeMiddlewareError<M: Middleware> {
    #[error("{0}")]
    MiddlewareError(M::Error),

    #[error(transparent)]
    ProviderError(#[from] ProviderError),

    #[error("Provided GasFeeSpeed is invalid")]
    InvalidGasFeeSpeed,
}

impl<M: Middleware> MiddlewareError for GasFeeMiddlewareError<M> {
    type Inner = M::Error;

    fn from_err(src: M::Error) -> Self {
        GasFeeMiddlewareError::MiddlewareError(src)
    }

    fn as_inner(&self) -> Option<&Self::Inner> {
        match self {
            GasFeeMiddlewareError::MiddlewareError(e) => Some(e),
            _ => None,
        }
    }
}

impl<M> GasFeeMiddleware<M>
where
    M: Middleware,
{
    pub fn new(
        inner: M,
        gas_fee_speed: Option<GasFeeSpeed>,
    ) -> Result<Self, GasFeeMiddlewareError<M>> {
        Ok(Self {
            inner,
            gas_fee_speed,
        })
    }
}

#[async_trait]
impl<M> Middleware for GasFeeMiddleware<M>
where
    M: Middleware,
{
    type Error = GasFeeMiddlewareError<M>;
    type Provider = M::Provider;
    type Inner = M;

    fn inner(&self) -> &M {
        &self.inner
    }

    async fn fill_transaction(
        &self,
        tx: &mut TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<(), Self::Error> {
        if let TypedTransaction::Eip1559(ref mut inner) = tx {
                if inner.max_fee_per_gas.is_none() || inner.max_priority_fee_per_gas.is_none() {
                    let (max_fee_per_gas, max_priority_fee_per_gas) =
                        self.estimate_eip1559_fees(None).await?;
                    // we want to avoid overriding the user if either of these
                    // are set. In order to do this, we refuse to override the
                    // `max_fee_per_gas` if already set.
                    // However, we must preserve the constraint that the tip
                    // cannot be higher than max fee, so we override user
                    // intent if that is so. We override by
                    //   - first: if set, set to the min(current value, MFPG)
                    //   - second, if still unset, use the RPC estimated amount
                    let mfpg = inner.max_fee_per_gas.get_or_insert(max_fee_per_gas);
                    inner.max_priority_fee_per_gas = inner
                        .max_priority_fee_per_gas
                        .map(|tip| std::cmp::min(tip, *mfpg))
                        .or(Some(max_priority_fee_per_gas));
                };
            };

        Ok(())
    }
}
