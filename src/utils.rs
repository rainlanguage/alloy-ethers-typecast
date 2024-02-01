use ethers::types::{U256, U512};
use std::ops::Div;
use thiserror::Error;
use tracing::debug;

/// EIP-1559 fee estimator that takes the mean of rewards paid in the past
/// This can be plugged into ethers estimator function
pub fn eip1559_fee_estimator(base_fee_per_gas: U256, tips_history: Vec<Vec<U256>>) -> (U256, U256) {
    let tips_history_flat: Vec<U256> = tips_history.clone().into_iter().flatten().collect();
    let max_priority_fee_per_gas = checked_average(tips_history_flat.clone())
        .unwrap_or(*tips_history_flat.last().unwrap_or(&U256::from(50)));
    let max_fee_per_gas = base_fee_per_gas + max_priority_fee_per_gas;

    debug!("max_fee_per_gas {:?}", max_fee_per_gas);
    debug!("max_priority_fee_per_gas {:?}", max_priority_fee_per_gas);

    (max_fee_per_gas, max_priority_fee_per_gas)
}

#[derive(Error, Debug)]
pub enum CheckedAverageError {
    #[error("Overflow")]
    Overflow,
    #[error("TryFrom U512 -> U256 Error")]
    TryFromU512,
}

fn checked_average(numbers: Vec<U256>) -> Result<U256, CheckedAverageError> {
    let mut total = U512::from(0);
    for n in numbers.iter() {
        total = total
            .checked_add(U512::from(n))
            .ok_or(CheckedAverageError::Overflow)?;
    }
    debug!("Calculated total {:?}", total);
    debug!("Length {:?}", numbers.len());

    let average =
        U256::try_from(total.div(numbers.len())).map_err(|_| CheckedAverageError::TryFromU512)?;
    debug!("Calculated average {:?}", average);

    Ok(average)
}
