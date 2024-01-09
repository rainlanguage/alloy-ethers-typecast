mod request_shim;

/// Converts [ethers::types::Address] to [alloy_primitives::Address]
pub fn ethers_address_to_alloy(address: ethers::types::Address) -> alloy_primitives::Address {
    address.to_fixed_bytes().into()
}

/// Converts [alloy_primitives::Address] to [ethers::types::Address]
pub fn alloy_address_to_ethers(address: alloy_primitives::Address) -> ethers::types::Address {
    ethers::types::H160::from(address.into_array())
}

/// Converts [ethers::types::U256] to [alloy_primitives::U256]
pub fn ethers_u256_to_alloy(value: ethers::types::U256) -> alloy_primitives::U256 {
    let mut data = [0_u8; 32];
    value.to_little_endian(&mut data);
    alloy_primitives::U256::from_le_slice(&data)
}

/// Converts [alloy_primitives::U256] to [ethers::types::U256]
pub fn alloy_u256_to_ethers(value: alloy_primitives::U256) -> ethers::types::U256 {
    let data = value.as_le_slice();
    ethers::types::U256::from_little_endian(data)
}

/// Converts [ethers::types::U64] to [alloy_primitives::U64]
pub fn ethers_u64_to_alloy(value: ethers::types::U64) -> alloy_primitives::U64 {
    let mut data = [0_u8; 8];
    value.to_little_endian(&mut data);
    alloy_primitives::U64::from_le_slice(&data)
}

/// Converts [alloy_primitives::U64] to [ethers::types::U64]
pub fn alloy_u64_to_ethers(value: alloy_primitives::U64) -> ethers::types::U64 {
    let data = value.as_le_slice();
    ethers::types::U64::from_little_endian(data)
}

/// Converts [ethers::types::Bytes] to [alloy_primitives::Bytes]
pub fn ethers_bytes_to_alloy(bytes: ethers::types::Bytes) -> alloy_primitives::Bytes {
    bytes.to_vec().into()
}

/// Converts [alloy_primitives::Bytes]to [ethers::types::Bytes]
pub fn alloy_bytes_to_ethers(bytes: alloy_primitives::Bytes) -> ethers::types::Bytes {
    bytes.to_vec().into()
}

#[cfg(test)]
pub mod test {
    use crate::{
        alloy_address_to_ethers, alloy_bytes_to_ethers, alloy_u256_to_ethers,
        ethers_address_to_alloy, ethers_bytes_to_alloy, ethers_u256_to_alloy,
    };
    use ethers::core::rand::random;

    #[test]
    pub fn test_ethers_address_to_alloy() {
        for _i in 0..10 {
            let ethers_address = ethers::types::H160::random();
            let alloy_address = ethers_address_to_alloy(ethers_address);
            assert!(ethers_address.eq(&alloy_address_to_ethers(alloy_address)))
        }
    }

    #[test]
    pub fn test_alloy_address_to_ethers() {
        for _i in 0..10 {
            let alloy_address = alloy_primitives::Address::random();
            let ethers_address = alloy_address_to_ethers(alloy_address);
            assert!(alloy_address.eq(&ethers_address_to_alloy(ethers_address)));
        }
    }

    #[test]
    pub fn test_ethers_u256_to_alloy() {
        for _i in 0..10 {
            let ethers_u256 = ethers::types::U256::from(random::<u128>());
            let alloy_u256 = ethers_u256_to_alloy(ethers_u256);
            assert!(ethers_u256.eq(&alloy_u256_to_ethers(alloy_u256)));
        }
    }

    #[test]
    pub fn test_alloy_u256_to_ethers() {
        for _i in 0..10 {
            let alloy_u256 = alloy_primitives::U256::from(random::<u128>());
            let ethers_u256 = alloy_u256_to_ethers(alloy_u256);
            assert!(alloy_u256.eq(&ethers_u256_to_alloy(ethers_u256)));
        }
    }

    #[test]
    pub fn test_ethers_bytes_to_alloy() {
        for _i in 0..10 {
            let random_bytes: Vec<u8> = (0..1024).map(|_| random::<u8>()).collect();
            let ethers_bytes = ethers::types::Bytes::from(random_bytes);
            let alloy_bytes = ethers_bytes_to_alloy(ethers_bytes.clone());
            assert!(ethers_bytes.eq(&alloy_bytes_to_ethers(alloy_bytes)));
        }
    }

    #[test]
    pub fn test_alloy_bytes_to_ethers() {
        for _i in 0..10 {
            let random_bytes: Vec<u8> = (0..1024).map(|_| random::<u8>()).collect();
            let alloy_bytes = alloy_primitives::Bytes::from(random_bytes);
            let ethers_bytes = alloy_bytes_to_ethers(alloy_bytes.clone());
            assert!(alloy_bytes.eq(&ethers_bytes_to_alloy(ethers_bytes)));
        }
    }
}
