use ethers::types::{U256, U512};
use std::ops::Div;
use thiserror::Error;

/// Determine EIP1559 fees from a base fee and an array of rewards paid in past blocks
pub fn eip1559_fee_estimator(base_fee_per_gas: U256, rewards_history: Vec<U256>) -> (U256, U256) {
    let max_priority_fee_per_gas = checked_average(rewards_history.clone())
        .unwrap_or(*rewards_history.last().unwrap_or(&U256::from(50)));
    let max_fee_per_gas = base_fee_per_gas + max_priority_fee_per_gas;

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
    let average =
        U256::try_from(total.div(numbers.len())).map_err(|_| CheckedAverageError::TryFromU512)?;

    Ok(average)
}
