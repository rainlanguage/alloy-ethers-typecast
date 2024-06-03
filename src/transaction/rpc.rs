use ethers::{
    types::{transaction::eip2718::TypedTransaction, BlockId, BlockNumber, U64},
    utils,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::request_shim::{AlloyTransactionRequest, TransactionRequestShim};

/// A JSON-RPC request, taken from ethers since it is private
/// https://github.com/gakonst/ethers-rs/blob/master/ethers-providers/src/rpc/transports/common.rs
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Request<T> {
    id: u64,
    jsonrpc: String,
    method: String,
    params: T,
}
impl<T> Request<T> {
    /// Creates a new JSON RPC request
    pub fn new(id: u64, method: &str, params: T) -> Self {
        Self {
            id,
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
        }
    }

    /// creates a new eth_call rpc request from the given transaction and block
    pub fn new_call_request(
        id: u64,
        transaction: &AlloyTransactionRequest,
        block: Option<u64>,
    ) -> Request<[Value; 2]> {
        let tx = utils::serialize(&TypedTransaction::Eip1559(transaction.to_eip1559()));
        let block = utils::serialize::<BlockId>(
            &block
                .map(|v| BlockNumber::Number(U64::from(v)))
                .unwrap_or(BlockNumber::Latest)
                .into(),
        );
        Request {
            id,
            jsonrpc: "2.0".to_string(),
            method: "eth_call".to_string(),
            params: [tx, block],
        }
    }
}

impl<T: Serialize> Request<T> {
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }
}

/// A JSON-RPC response, taken from ethers since it is private
/// https://github.com/gakonst/ethers-rs/blob/master/ethers-providers/src/rpc/transports/common.rs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response {
    Success {
        jsonrpc: String,
        id: u64,
        // hex string data
        result: String,
    },
    Error {
        jsonrpc: String,
        id: u64,
        error: Error,
    },
}
impl Response {
    pub fn new_success(id: u64, result_data: &str) -> Self {
        Response::Success {
            id,
            jsonrpc: "2.0".to_string(),
            result: result_data.to_string(),
        }
    }

    pub fn new_error(id: u64, code: i64, message: &str, data: Option<&str>) -> Self {
        Response::Error {
            id,
            jsonrpc: "2.0".to_string(),
            error: Error {
                code,
                message: message.to_string(),
                data: data.map(Into::into),
            },
        }
    }

    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&self)
    }
}

/// A JSON-RPC 2.0 error, taken from ethers since it is private
/// https://github.com/gakonst/ethers-rs/blob/master/ethers-providers/src/rpc/transports/common.rs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Error {
    /// The error code
    pub code: i64,
    /// The error message
    pub message: String,
    /// Additional data
    pub data: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

    #[test]
    fn test_response_to_json() {
        let response = Response::new_success(1, "0x1234");
        let result = response.to_json_string().unwrap();
        let expected = r#"{"jsonrpc":"2.0","id":1,"result":"0x1234"}"#.to_string();
        assert_eq!(result, expected);

        let response = Response::new_error(1, -32003, "execution reverted", Some("0x00"));
        let result = response.to_json_string().unwrap();
        let expected = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32003,"message":"execution reverted","data":"0x00"}}"#.to_string();
        assert_eq!(result, expected);
    }

    #[test]
    fn test_request_to_json() {
        let address = Address::random();
        let data = alloy_primitives::hex::decode("0x1234").unwrap();
        let transaction = AlloyTransactionRequest::new()
            .with_to(Some(address))
            .with_data(Some(data));
        let result = Request::<[Value; 2]>::new_call_request(1, &transaction, None)
            .to_json_string()
            .unwrap();
        let expected = format!(
            r#"{{"id":1,"jsonrpc":"2.0","method":"eth_call","params":[{{"accessList":[],"data":"0x1234","to":"{}"}},"latest"]}}"#,
            address.to_string().to_ascii_lowercase()
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn test_new_call_request() {
        let address = Address::random();
        let data = alloy_primitives::hex::decode("0x1234").unwrap();
        let transaction = AlloyTransactionRequest::new()
            .with_to(Some(address))
            .with_data(Some(data));
        let result = Request::<[Value; 2]>::new_call_request(1, &transaction, None);
        let expected = Request {
            id: 1,
            jsonrpc: "2.0".to_string(),
            method: "eth_call".to_string(),
            params: [
                serde_json::json!({
                    "accessList":[],
                    "data":"0x1234",
                    "to":address.to_string().to_ascii_lowercase()
                }),
                Value::String("latest".to_string()),
            ],
        };
        assert_eq!(result, expected);
    }
}
