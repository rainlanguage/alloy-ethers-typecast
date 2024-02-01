use average::WeightedMean;
use ethers::types::U256;

/// EIP-1559 fee estimator that takes the weighted mean of rewards paid in the past
/// This can be plugged into ethers estimator function
pub fn eip1559_fee_estimator_weighted_average(
    base_fee_per_gas: U256,
    tips_history: Vec<Vec<U256>>,
) -> (U256, U256) {
    let weights = 1..tips_history.len();
    let tip_history_wmean: WeightedMean = tips_history
        .into_iter()
        .zip(weights)
        .map(|(val, weight)| (val[0].as_u64() as f64, weight as f64))
        .collect();

    let max_priority_fee_per_gas = U256::from(tip_history_wmean.mean().floor() as u64);
    let max_fee_per_gas = base_fee_per_gas + max_priority_fee_per_gas;

    (max_fee_per_gas, max_priority_fee_per_gas)
}
