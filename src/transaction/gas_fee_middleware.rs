use async_trait::async_trait;
use ethers::core::types::{transaction::eip2718::TypedTransaction, BlockId};
use ethers::providers::{Middleware, MiddlewareError, ProviderError};
use ethers::types::BlockNumber;
use ethers::utils;
use thiserror::Error;
use serde::{Serialize, Deserialize};

const EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_SLOW: f64 = 25.0;
const EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_MEDIUM: f64 = 50.0;
const EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_FAST: f64 = 75.0;
const EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_INSTANT: f64 = 90.0;

const EIP1559_FEE_ESTIMATION_REWARD_PERCENTILES: [f64; 4] = [
    EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_SLOW,
    EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_MEDIUM,
    EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_FAST,
    EIP1559_FEE_ESTIMATION_REWARD_PERCENTILE_INSTANT,
];

#[derive(Serialize, Deserialize, Debug, Clone)]
#[repr(u8)]
pub enum GasFeeSpeed {
    Slow,
    Medium,
    Fast,
    Instant,
}

#[derive(Debug)]
pub struct GasFeeMiddleware<M> {
    inner: M,
    fee_history_percentile: f64,
}

#[derive(Error, Debug)]
pub enum GasFeeMiddlewareError<M: Middleware> {
    #[error("{0}")]
    MiddlewareError(M::Error),

    #[error(transparent)]
    ProviderError(#[from] ProviderError),
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
    pub fn new(inner: M, speed: GasFeeSpeed) -> Self {
        Self {
            inner,
            fee_history_percentile: EIP1559_FEE_ESTIMATION_REWARD_PERCENTILES[speed as usize],
        }
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

    /// Override the fill_transaction function with our own gas fee estimation.
    /// Specify a fee percentile for the eth_feeHistory call, based on the desired transaction speed GasFeeSpeed.
    /// Then use the default ethers estimator function to calculate a max fee and max priority fee from the history.
    async fn fill_transaction(
        &self,
        tx: &mut TypedTransaction,
        block: Option<BlockId>,
    ) -> Result<(), Self::Error> {
        if let TypedTransaction::Eip1559(ref mut inner_tx) = tx {
            let base_fee_per_gas = self
                .get_block(BlockNumber::Latest)
                .await?
                .ok_or_else(|| ProviderError::CustomError("Latest block not found".into()))?
                .base_fee_per_gas
                .ok_or_else(|| ProviderError::CustomError("EIP-1559 not activated".into()))?;

            let fee_history = self
                .fee_history(
                    utils::EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
                    BlockNumber::Latest,
                    &[self.fee_history_percentile],
                )
                .await?;
            let (max_fee_per_gas, max_priority_fee_per_gas) =
                utils::eip1559_default_estimator(base_fee_per_gas, fee_history.reward);

            inner_tx.max_fee_per_gas = Some(max_fee_per_gas);
            inner_tx.max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
        }

        let _ = self
            .inner()
            .fill_transaction(tx, block)
            .await
            .map_err(GasFeeMiddlewareError::MiddlewareError)?;

        Ok(())
    }
}
