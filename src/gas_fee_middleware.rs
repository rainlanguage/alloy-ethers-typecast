use crate::utils::eip1559_fee_estimator;
use async_trait::async_trait;
use ethers::core::types::{transaction::eip2718::TypedTransaction, BlockId};

use ethers::providers::{Middleware, MiddlewareError, ProviderError};
use ethers::types::BlockNumber;
use serde::{Deserialize, Serialize};
use thiserror::Error;


const GAS_FEE_SPEED_DEFAULT: GasFeeSpeed = GasFeeSpeed::Medium;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum GasFeeSpeed {
    Slow,
    Medium,
    Fast,
    Fastest,
}

impl GasFeeSpeed {
    fn to_percentile(&self) -> f64 {
        match self {
            GasFeeSpeed::Slow => 25.0,
            GasFeeSpeed::Medium => 50.0,
            GasFeeSpeed::Fast => 75.0,
            GasFeeSpeed::Fastest => 90.0,
        }
    }
}

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
                let base_fee_per_gas = self
                    .get_block(BlockNumber::Latest)
                    .await?
                    .ok_or_else(|| ProviderError::CustomError("Latest block not found".into()))?
                    .base_fee_per_gas
                    .ok_or_else(|| ProviderError::CustomError("EIP-1559 not activated".into()))?;

                let reward_history_percentile = self
                    .gas_fee_speed
                    .clone()
                    .unwrap_or(GAS_FEE_SPEED_DEFAULT)
                    .to_percentile();
                let fee_history = self
                    .fee_history(
                        ethers::utils::EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
                        BlockNumber::Latest,
                        &[reward_history_percentile],
                    )
                    .await?;

                let (max_fee_per_gas, max_priority_fee_per_gas) =
                    eip1559_fee_estimator(base_fee_per_gas, fee_history.reward);
                inner.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
                inner.max_fee_per_gas = Some(max_fee_per_gas);
            };
        };

        self.inner()
            .fill_transaction(tx, block)
            .await
            .map_err(|e| GasFeeMiddlewareError::MiddlewareError(e))
    }
}
