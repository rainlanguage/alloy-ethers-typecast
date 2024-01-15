use crate::ethers_bytes_to_alloy;
use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};
use alloy_sol_types::SolCall;
use ethers::middleware::SignerMiddleware;
use ethers::providers::{JsonRpcClient, Middleware, Provider, ProviderError};
use ethers::signers::Signer;
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::types::{Bytes, Eip1559TransactionRequest, TransactionReceipt};
use ethers::utils::hex;
use tracing::info;

pub struct WriteTransaction<M: Middleware, S: Signer> {
    pub transaction_request: Eip1559TransactionRequest,
    pub client: SignerMiddleware<M, S>,
}

impl<M: Middleware, S: Signer> WriteTransaction<M, S> {
    pub async fn from_alloy_transaction_request(
        transaction_request: AlloyTransactionRequest,
        client: SignerMiddleware<M, S>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            transaction_request: transaction_request.to_eip1559(),
            client,
        })
    }

    pub async fn from_ethers_transaction_request(
        transaction_request: Eip1559TransactionRequest,
        client: SignerMiddleware<M, S>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            transaction_request,
            client,
        })
    }

    // Execute the transaction
    pub async fn write(&self) -> anyhow::Result<TransactionReceipt> {
        let pending_tx = self
            .client
            .send_transaction(self.transaction_request.clone(), None)
            .await
            .map_err(|err| anyhow::anyhow!("{}", err))?;

        info!("Transaction submitted. Awaiting block confirmations...");

        let tx_confirmation = pending_tx.confirmations(4).await?;

        let tx_receipt = match tx_confirmation {
            Some(receipt) => receipt,
            None => return Err(anyhow::anyhow!("Transaction failed")),
        };

        info!("Transaction Confirmed");
        info!(
            "✅ Hash : 0x{}",
            hex::encode(tx_receipt.transaction_hash.as_bytes())
        );
        Ok(tx_receipt)
    }
}

pub struct ReadTransaction<P: JsonRpcClient> {
    pub transaction_request: Eip1559TransactionRequest,
    pub client: Provider<P>,
}

impl<P: JsonRpcClient> ReadTransaction<P> {
    pub async fn from_alloy_transaction_request(
        transaction_request: AlloyTransactionRequest,
        client: Provider<P>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            transaction_request: transaction_request.to_eip1559(),
            client,
        })
    }

    pub async fn from_ethers_transaction_request(
        transaction_request: Eip1559TransactionRequest,
        client: Provider<P>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            transaction_request: transaction_request,
            client,
        })
    }

    async fn read(&self) -> anyhow::Result<Bytes> {
        let res = self
            .client
            .call(
                &TypedTransaction::Eip1559(self.transaction_request.clone()),
                None,
            )
            .await
            .map_err(|err| match err {
                ProviderError::JsonRpcClientError(err) => {
                    anyhow::anyhow!("{}", err)
                }
                _ => anyhow::anyhow!("{}", err),
            })?;
        Ok(res)
    }

    pub async fn read_to_ethers_bytes(&self) -> anyhow::Result<Bytes> {
        let res = self.read().await?;
        Ok(res)
    }

    pub async fn read_to_alloy_bytes(&self) -> anyhow::Result<alloy_primitives::Bytes> {
        let bytes = self.read().await?;
        Ok(ethers_bytes_to_alloy(bytes))
    }

    pub async fn read_to_alloy_bytes_typed<T: SolCall>(
        &self,
    ) -> anyhow::Result<<T as SolCall>::Return> {
        let bytes = self.read().await?;
        let t = T::abi_decode_returns(bytes.to_vec().as_slice(), true)?;
        Ok(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};
    use alloy_sol_types::sol;
    use ethers::providers::{MockProvider, MockResponse};
    use serde_json::json;

    sol! {
       function foo(uint256 a, uint256 b) external view returns (Foo);

        struct Foo {
            uint256 bar;
            address baz;
        }
    }

    #[tokio::test]
    async fn test_read_to_alloy_bytes_typed() -> anyhow::Result<()> {
        // Create a mock Provider
        let mock_provider = MockProvider::new();

        let bytes_string = "0x000000000000000000000000000000000000000000000000000000000000002a0000000000000000000000001111111111111111111111111111111111111111";

        // Create a mock response
        let foo_response = json!(bytes_string);

        let mock_response = MockResponse::Value(foo_response);
        mock_provider.push_response(mock_response.clone());
        mock_provider.push_response(mock_response.clone());
        mock_provider.push_response(mock_response);

        // Create a Provider instance with the mock provider
        let client = Provider::new(mock_provider);

        // Create a mock transaction request
        let transaction_request = Eip1559TransactionRequest::default();

        // Create a ReadTransaction instance with the mock transaction request and provider
        let read_transaction =
            ReadTransaction::from_ethers_transaction_request(transaction_request, client).await?;

        // Call the read_to_ethers_bytes method
        let ethers_bytes = read_transaction.read_to_ethers_bytes().await?;

        assert_eq!(
            ethers_bytes,
            ethers::types::Bytes::from(hex::decode(bytes_string).unwrap())
        );

        // Call the read_to_alloy_bytes method
        let alloy_bytes = read_transaction.read_to_alloy_bytes().await?;

        assert_eq!(
            alloy_bytes,
            alloy_primitives::Bytes::from(hex::decode(bytes_string).unwrap())
        );

        // Call the read_to_alloy_bytes_typed method
        let result = read_transaction
            .read_to_alloy_bytes_typed::<fooCall>()
            .await?;

        let bar = result._0.bar;
        let baz = result._0.baz;

        assert_eq!(bar, U256::from(42));
        assert_eq!(baz, Address::repeat_byte(0x11));

        Ok(())
    }
}
