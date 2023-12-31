## Crate for Safe Typecasting between Ethers and Alloy types
Currently supporting type conversion for:
- `ethers::types::H160`       to `alloy_primitives::Address`
- `alloy_primitives::Address` to `ethers::types::H160`
- `ethers::types::U256`       to `alloy_primitives::U256`
- `alloy_primitives::U256`    to `ethers::types::U256`
- `ethers::types::Bytes`      to `alloy_primitives::Bytes`
- `alloy_primitives::Bytes`   to `ethers::types::Bytes`

## Example
```sh
let ethers_address: ethers::types::H160 = ethers::types::H160::random();
let alloy_address: alloy_primitives::Address = ethers_address_to_alloy(ethers_address);
```
```sh
let ethers_u256: ethers::types::U256 = ethers::types::U256::from_dec_str("126731272983");
let alloy_u256: alloy_primitives::U256 = ethers_u256_to_alloy(ethers_u256);
```