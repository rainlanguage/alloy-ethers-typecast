use alloy_primitives::{Address, U256, U64};
use ethers::types::{Eip1559TransactionRequest, NameOrAddress, H160};

trait TransactionRequestShim {
    fn to_eip1559(&self) -> Eip1559TransactionRequest;
}

/// Parameters for sending a transaction
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct AlloyTransactionRequest {
    /// Sender address or ENS name
    pub from: Option<Address>,

    /// Recipient address (None for contract creation)
    pub to: Option<Address>,

    /// Supplied gas (None for sensible default)
    pub gas: Option<U256>,

    /// Transferred value (None for no transfer)
    pub value: Option<U256>,

    /// The compiled code of a contract OR the first 4 bytes of the hash of the
    /// invoked method signature and encoded parameters. For details see Ethereum Contract ABI
    pub data: Option<Vec<u8>>,

    /// Transaction nonce (None for next available nonce)
    pub nonce: Option<U256>,

    /// Represents the maximum tx fee that will go to the miner as part of the user's
    /// fee payment. It serves 3 purposes:
    /// 1. Compensates miners for the uncle/ommer risk + fixed costs of including transaction in a
    /// block;
    /// 2. Allows users with high opportunity costs to pay a premium to miners;
    /// 3. In times where demand exceeds the available block space (i.e. 100% full, 30mm gas),
    /// this component allows first price auctions (i.e. the pre-1559 fee model) to happen on the
    /// priority fee.
    ///
    /// More context [here](https://hackmd.io/@q8X_WM2nTfu6nuvAzqXiTQ/1559-wallets)
    pub max_priority_fee_per_gas: Option<U256>,

    /// Represents the maximum amount that a user is willing to pay for their tx (inclusive of
    /// baseFeePerGas and maxPriorityFeePerGas). The difference between maxFeePerGas and
    /// baseFeePerGas + maxPriorityFeePerGas is “refunded” to the user.
    pub max_fee_per_gas: Option<U256>,

    /// Chain ID (None for mainnet)
    pub chain_id: Option<U64>,
}

impl AlloyTransactionRequest {
    pub fn new() -> Self {
        Self::default()
    }

    // Builder pattern helpers

    /// Sets the `from` field in the transaction to the provided value
    #[must_use]
    pub fn from<T: Into<Address>>(mut self, from: T) -> Self {
        self.from = Some(from.into());
        self
    }

    /// Sets the `to` field in the transaction to the provided value
    #[must_use]
    pub fn to<T: Into<Address>>(mut self, to: T) -> Self {
        self.to = Some(to.into());
        self
    }

    /// Sets the `gas` field in the transaction to the provided value
    #[must_use]
    pub fn gas<T: Into<U256>>(mut self, gas: T) -> Self {
        self.gas = Some(gas.into());
        self
    }

    /// Sets the `max_priority_fee_per_gas` field in the transaction to the provided value
    #[must_use]
    pub fn max_priority_fee_per_gas<T: Into<U256>>(mut self, max_priority_fee_per_gas: T) -> Self {
        self.max_priority_fee_per_gas = Some(max_priority_fee_per_gas.into());
        self
    }

    /// Sets the `max_fee_per_gas` field in the transaction to the provided value
    #[must_use]
    pub fn max_fee_per_gas<T: Into<U256>>(mut self, max_fee_per_gas: T) -> Self {
        self.max_fee_per_gas = Some(max_fee_per_gas.into());
        self
    }

    /// Sets the `value` field in the transaction to the provided value
    #[must_use]
    pub fn value<T: Into<U256>>(mut self, value: T) -> Self {
        self.value = Some(value.into());
        self
    }

    /// Sets the `data` field in the transaction to the provided value
    #[must_use]
    pub fn data<T: Into<Vec<u8>>>(mut self, data: T) -> Self {
        self.data = Some(data.into());
        self
    }

    /// Sets the `nonce` field in the transaction to the provided value
    #[must_use]
    pub fn nonce<T: Into<U256>>(mut self, nonce: T) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    /// Sets the `chain_id` field in the transaction to the provided value
    #[must_use]
    pub fn chain_id<T: Into<U64>>(mut self, chain_id: T) -> Self {
        self.chain_id = Some(chain_id.into());
        self
    }
}

impl TransactionRequestShim for AlloyTransactionRequest {
    fn to_eip1559(&self) -> Eip1559TransactionRequest {
        let mut tx = Eip1559TransactionRequest::new();
        tx.to = self.to.map(|to| NameOrAddress::Address(H160(to.0 .0)));
        tx.from = self.from.map(|from| H160(from.0 .0));
        tx.gas = self
            .gas
            .map(|gas| ethers::types::U256::from_little_endian(gas.as_le_slice()));
        tx.nonce = self
            .nonce
            .map(|nonce| ethers::types::U256::from_little_endian(nonce.as_le_slice()));
        tx.max_priority_fee_per_gas =
            self.max_priority_fee_per_gas
                .map(|max_priority_fee_per_gas| {
                    ethers::types::U256::from_little_endian(max_priority_fee_per_gas.as_le_slice())
                });
        tx.max_fee_per_gas = self.max_fee_per_gas.map(|max_fee_per_gas| {
            ethers::types::U256::from_little_endian(max_fee_per_gas.as_le_slice())
        });
        tx.value = self
            .value
            .map(|value| ethers::types::U256::from_little_endian(value.as_le_slice()));
        tx.data = self
            .data
            .clone()
            .map(|data| ethers::types::Bytes::from(data));
        tx.chain_id = self
            .chain_id
            .map(|chain_id| ethers::types::U64::from_little_endian(chain_id.as_le_slice()));
        tx
    }
}

#[cfg(test)]
mod tests {
    use ethers::types::transaction::eip2930::AccessList;

    use super::*;
    #[test]
    fn test_to_eip1559() {
        let request = AlloyTransactionRequest {
            to: Some(Address::repeat_byte(2)),
            from: Some(Address::repeat_byte(1)),
            gas: Some(U256::from(100000)),
            value: Some(U256::from(12345)),
            data: Some(vec![1, 2, 3]),
            nonce: Some(U256::from(0)),
            max_priority_fee_per_gas: Some(U256::from(100)),
            max_fee_per_gas: Some(U256::from(200)),
            chain_id: Some(U64::from(1)),
        };

        let expected = Eip1559TransactionRequest {
            to: Some(NameOrAddress::Address(H160([2; 20]))),
            from: Some(H160([1; 20])),
            gas: Some(ethers::types::U256::from(100000)),
            value: Some(ethers::types::U256::from(12345)),
            data: Some(ethers::types::Bytes::from(vec![1, 2, 3])),
            nonce: Some(ethers::types::U256::from(0 )),
            max_priority_fee_per_gas: Some(ethers::types::U256::from(100)),
            access_list: AccessList::default(),
            max_fee_per_gas: Some(ethers::types::U256::from(200)),
            chain_id: Some(ethers::types::U64::from(1)),
        };

        assert_eq!(request.to_eip1559(), expected);
    }

    #[test]
    fn test_builder_functions() {
        let request = AlloyTransactionRequest::default()
            .from(Address::repeat_byte(1))
            .to(Address::repeat_byte(2))
            .gas(U256::from(100000))
            .value(U256::from(12345))
            .data(vec![1, 2, 3])
            .nonce(U256::from(0))
            .max_priority_fee_per_gas(U256::from(100))
            .max_fee_per_gas(U256::from(200))
            .chain_id(U64::from(1));

        assert_eq!(request.from, Some(Address::repeat_byte(1)));
        assert_eq!(request.to, Some(Address::repeat_byte(2)));
        assert_eq!(request.gas, Some(U256::from(100000)));
        assert_eq!(request.value, Some(U256::from(12345)));
        assert_eq!(request.data, Some(vec![1, 2, 3]));
        assert_eq!(request.nonce, Some(U256::from(0)));
        assert_eq!(request.max_priority_fee_per_gas, Some(U256::from(100)));
        assert_eq!(request.max_fee_per_gas, Some(U256::from(200)));
        assert_eq!(request.chain_id, Some(U64::from(1)));
    }
}
