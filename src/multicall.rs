use crate::transaction::{ReadContractParameters, ReadableClient, ReadableClientError};
use alloy_primitives::{hex::FromHex, Address, U64};
use alloy_sol_types::{sol, SolCall};
use ethers::providers::JsonRpcClient;
use thiserror::Error;

/// Multicall3 contract address on all supported chains
/// safe to say Multicall3 is deployed at this address on all major evm chains,
/// except a few handful of chains, notably zkSyncEra, Tron, and few testnets
/// see: https://www.multicall3.com/deployments
pub const MULTICALL3_ADDRESS: &str = "0xcA11bde05977b3631167028862bE2a173976CA11";

sol! {
    interface IMulticall3 {
        struct Call3 {
            address target;
            bool allowFailure;
            bytes callData;
        }
        struct Result {
            bool success;
            bytes returnData;
        }
        function aggregate3(Call3[] calldata calls) external payable returns (Result[] memory returnData);
    }
}

#[derive(Error, Debug)]
pub enum MulticallError {
    #[error(transparent)]
    ClientError(#[from] ReadableClientError),

    #[error(transparent)]
    AlloySolTypesError(#[from] alloy_sol_types::Error),

    #[error("Multicall item failed")]
    MulticallItemFailed(Vec<u8>),
}

/// A single Multicall call item typed with alloy SollCal
#[derive(Debug, Clone)]
pub struct MulticallCallItem<T: SolCall> {
    pub address: Address,
    pub call: T,
}

/// A struct that makes making multicall reads of same call types easy
#[derive(Debug, Clone)]
pub struct Multicall<T: SolCall> {
    pub calls: Vec<MulticallCallItem<T>>,
}

impl<T: SolCall> Default for Multicall<T> {
    fn default() -> Self {
        Multicall { calls: vec![] }
    }
}

impl<T: SolCall> Multicall<T> {
    /// adds a single call to the list of multicall calls
    pub fn add_call(&mut self, call: MulticallCallItem<T>) {
        self.calls.push(call);
    }

    /// clears the calls list
    pub fn clear_calls(&mut self) {
        self.calls.clear();
    }

    /// executes the read call using the provided JsonRpcClient with the calls already added to the list
    /// the Multicall3 address on all chains is the same, except a few that have unofficial deployments
    /// such as zkSynEra, so the default Multicall3 address can be overriden in the args
    pub async fn read(
        &self,
        provider: ReadableClient<impl JsonRpcClient>,
        block_number: Option<u64>,
        multicall_address_override: Option<Address>,
    ) -> Result<Vec<Result<Result<T::Return, MulticallError>, MulticallError>>, MulticallError>
    {
        let calls = self
            .calls
            .iter()
            .map(|v| self::IMulticall3::Call3 {
                allowFailure: true,
                target: v.address,
                callData: v.call.abi_encode(),
            })
            .collect::<Vec<self::IMulticall3::Call3>>();

        let params = ReadContractParameters {
            address: multicall_address_override
                .unwrap_or(Address::from_hex(MULTICALL3_ADDRESS).unwrap()),
            call: self::IMulticall3::aggregate3Call { calls },
            block_number: block_number.map(U64::from),
        };

        let result = provider.read(params).await?;

        Ok(result
            .returnData
            .iter()
            .map(|v| {
                if v.success {
                    Ok(T::abi_decode_returns(&v.returnData, true).map_err(Into::into))
                } else {
                    Err(MulticallError::MulticallItemFailed(v.returnData.clone()))
                }
            })
            .collect::<Vec<Result<Result<T::Return, MulticallError>, MulticallError>>>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_multicall_read() -> anyhow::Result<()> {
        sol! {
            function symbol() public view returns (string memory);
        }
        let mut multicall = Multicall::default();

        let dai = Address::from_hex("0x8f3cf7ad23cd3cadbd9735aff958023239c6a063")?;
        let dai_symbol_call = MulticallCallItem {
            address: dai,
            call: symbolCall {},
        };
        multicall.add_call(dai_symbol_call);

        let usdc = Address::from_hex("0x2791bca1f2de4661ed88a30c99a7a9449aa84174")?;
        let usdc_symbol_call = MulticallCallItem {
            address: usdc,
            call: symbolCall {},
        };
        multicall.add_call(usdc_symbol_call);

        let provider = ReadableClient::new_from_url("https://rpc.ankr.com/polygon".to_owned())?;
        let result = multicall.read(provider, None, None).await?;
        let mut result_symbols = vec![];
        for res in result {
            result_symbols.push(res??._0);
        }

        let expected = vec!["DAI".to_string(), "USDC".to_string()];
        assert_eq!(result_symbols, expected);

        Ok(())
    }
}
