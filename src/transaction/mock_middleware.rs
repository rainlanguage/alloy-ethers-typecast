use std::fmt::{self, Debug};

use async_trait::async_trait;
use ethers::abi::AbiEncode;
use ethers::providers::{JsonRpcClient, ProviderError};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::utils::rlp;
use ethers::{
    core::types::*,
    providers::{Middleware, MiddlewareError, PendingTransaction},
    types::{Block, H256, U64},
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::json;
use thiserror::Error;
use tracing::debug;

// A mock middleware that noops on most calls.
#[derive(Debug, Clone)]
pub struct MockMiddleware<M> {
    inner: M,
    assert_data: Option<Bytes>,
    assert_to: Option<Address>,
}

impl<M> MockMiddleware<M>
where
    M: Middleware,
{
    /// `ìnner` the inner Middleware - ensure that if this is a provider, it is
    /// a mock provider that will confirm the transaction immediately.
    #[allow(dead_code)]
    pub fn new(inner: M) -> Result<Self, MockMiddlewareError<M>> {
        Ok(Self {
            inner,
            assert_data: None,
            assert_to: None,
        })
    }

    /// Sets the data that the next transaction should have
    #[allow(dead_code)]
    pub fn assert_next_data(&mut self, data: Bytes) {
        self.assert_data = Some(data);
    }

    /// Sets the to address that the next transaction should have.
    #[allow(dead_code)]
    pub fn assert_next_to(&mut self, to: Address) {
        self.assert_to = Some(to);
    }
}

#[async_trait]
impl<M> Middleware for MockMiddleware<M>
where
    M: Middleware,
{
    type Error = MockMiddlewareError<M>;
    type Provider = M::Provider;
    type Inner = M;

    fn inner(&self) -> &M {
        &self.inner
    }

    async fn send_transaction<T: Into<TypedTransaction> + Send + Sync>(
        &self,
        _tx: T,
        _block: Option<BlockId>,
    ) -> Result<PendingTransaction<'_, Self::Provider>, Self::Error> {
        Ok(
            PendingTransaction::new(H256::from_uint(&U256::from(1)), self.provider())
                .interval(std::time::Duration::from_secs(0)),
        )
    }

    async fn get_block_number(&self) -> Result<U64, Self::Error> {
        Ok(U64::zero())
    }

    async fn estimate_gas(
        &self,
        _tx: &TypedTransaction,
        _block: Option<BlockId>,
    ) -> Result<U256, Self::Error> {
        Ok(U256::zero())
    }

    async fn get_block<T: Into<BlockId> + Send + Sync>(
        &self,
        _block_hash_or_number: T,
    ) -> Result<Option<Block<TxHash>>, Self::Error> {
        Ok(Some(Block::default()))
    }

    async fn get_block_with_txs<T: Into<BlockId> + Send + Sync>(
        &self,
        _block_hash_or_number: T,
    ) -> Result<Option<Block<Transaction>>, Self::Error> {
        Ok(Some(Block::default()))
    }

    async fn get_uncle<T: Into<BlockId> + Send + Sync>(
        &self,
        _block_hash_or_number: T,
        _idx: U64,
    ) -> Result<Option<Block<H256>>, Self::Error> {
        Ok(Some(Block::default()))
    }

    async fn fill_transaction(
        &self,
        _tx: &mut TypedTransaction,
        _block: Option<BlockId>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    async fn send_raw_transaction<'a>(
        &'a self,
        _tx: Bytes,
    ) -> Result<PendingTransaction<'a, Self::Provider>, Self::Error> {
        // Deserialize the transaction from the bytes
        let tx: TypedTransaction = rlp::decode(_tx.as_ref())
            .map_err(|err| {
                debug!("Error: {:?}", err);
                ProviderError::CustomError("Failed to deserialize transaction".into())
            })
            .unwrap();

        // Check the data, if it's set
        if let Some(data) = &self.assert_data {
            assert_eq!(tx.data(), Some(data));
        }

        // Check the to address, if it's set
        if let Some(to) = &self.assert_to {
            debug!("Checking to address: {:?} == {:?}", tx.to(), Some(to));
            assert_eq!(tx.to(), Some(&NameOrAddress::Address(*to)));
        }
        Ok(
            PendingTransaction::new(H256::from_uint(&U256::from(1)), self.provider())
                .interval(std::time::Duration::from_secs(0)),
        )
    }

    async fn get_transaction<T: Send + Sync + Into<TxHash>>(
        &self,
        _transaction_hash: T,
    ) -> Result<Option<Transaction>, Self::Error> {
        Ok(Some(Transaction::default()))
    }

    async fn get_transaction_receipt<T: Send + Sync + Into<TxHash>>(
        &self,
        _transaction_hash: T,
    ) -> Result<Option<TransactionReceipt>, Self::Error> {
        Ok(Some(TransactionReceipt::default()))
    }
}

#[derive(Error, Debug)]
pub enum MockMiddlewareError<M: Middleware> {
    /// Thrown when the internal middleware errors
    #[error("{0}")]
    MiddlewareError(M::Error),
}

impl<M: Middleware> MiddlewareError for MockMiddlewareError<M> {
    type Inner = M::Error;

    fn from_err(src: M::Error) -> Self {
        MockMiddlewareError::MiddlewareError(src)
    }

    fn as_inner(&self) -> Option<&Self::Inner> {
        match self {
            MockMiddlewareError::MiddlewareError(e) => Some(e),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct MockJsonRpcClient;

impl MockJsonRpcClient {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl JsonRpcClient for MockJsonRpcClient {
    type Error = ProviderError;

    async fn request<T, R>(&self, _method: &str, _params: T) -> Result<R, Self::Error>
    where
        T: Debug + Serialize + Send + Sync,
        R: DeserializeOwned + Send,
    {
        match _method {
            "eth_getTransactionCount" => {
                debug!("MockJsonRpcClient: called eth_getTransactionCount");
                Ok(serde_json::from_value(json!("0x10")).map_err(|_| {
                    ProviderError::CustomError("Failed to deserialize response".into())
                })?)
            }
            "eth_getTransactionByHash" => {
                debug!("MockJsonRpcClient: called eth_getTransactionByHash");
                // Deserialize the hash
                let (hash,): (H256,) = serde_json::from_value(json!(_params)).map_err(|err| {
                    debug!("Error: {:?}", err);
                    ProviderError::CustomError("Failed to deserialize params".into())
                })?;

                let value = json!({
                    "hash": hash.encode_hex(),
                    "nonce": "0x00",
                    "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "blockNumber": "0x00",
                    "transactionIndex":  "0x00",
                    "from": "0x0000000000000000000000000000000000000000",
                    "to": "0x0000000000000000000000000000000000000000",
                    "value": "0x00",
                    "gasPrice": "0x00",
                    "gas": "0x00",
                    "input": "0x",
                    "v": "0x00",
                    "r": "0x0000000000000000000000000000000000000000000000000000000000000000",
                    "s": "0x0000000000000000000000000000000000000000000000000000000000000000"
                });
                let response: R = serde_json::from_value(value).map_err(|err| {
                    debug!("Error: {:?}", err);
                    ProviderError::CustomError("Failed to deserialize response".into())
                })?;
                Ok(response)
            }
            "eth_getTransactionReceipt" => {
                debug!("MockJsonRpcClient: called eth_getTransactionReceipt");
                // Deserialize the hash
                let (hash,): (H256,) = serde_json::from_value(json!(_params)).map_err(|err| {
                    debug!("Error: {:?}", err);
                    ProviderError::CustomError("Failed to deserialize params".into())
                })?;
                let value = json!({
                  "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                  "blockNumber":  "0x00",
                  "contractAddress": null,
                  "cumulativeGasUsed": "0x00",
                  "from": "0x0000000000000000000000000000000000000000",
                  "gasUsed": "0x00",
                  "logsBloom": format!("{:0512x}", 1),
                  "logs": [
                    {
                      "address": "0x0000000000000000000000000000000000000000",
                      "blockHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
                      "blockNumber": "0x00",
                      "data": "0x00",
                      "logIndex": "0x00",
                      "topics": [
                        "0x0000000000000000000000000000000000000000000000000000000000000000"
                      ],
                      "transactionHash": hash.encode_hex(),
                      "transactionIndex": format!("0x{:x}", 665)
                    }
                  ],
                  "root": "0x0000000000000000000000000000000000000000000000000000000000000000",
                  "to": "0x0000000000000000000000000000000000000000",
                  "transactionHash": hash.encode_hex(),
                  "transactionIndex": format!("0x{:x}", 665)
                });
                let response: R = serde_json::from_value(value).map_err(|err| {
                    debug!("Error: {:?}", err);
                    ProviderError::CustomError("Failed to deserialize response".into())
                })?;

                Ok(response)
            }
            _ => panic!(
                "MockJsonRpcClient method {:?} with params {:?} not implemented",
                _method, _params
            ),
        }
    }
}

impl fmt::Debug for MockJsonRpcClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MockJsonRpcClient")
    }
}
