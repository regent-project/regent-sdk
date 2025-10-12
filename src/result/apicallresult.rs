use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiCallResult {
    pub rc: Option<i32>,
    pub output: Option<String>,
    pub status: ApiCallStatus,
}

impl ApiCallResult {
    pub fn new() -> ApiCallResult {
        ApiCallResult {
            rc: None,
            output: None,
            status: ApiCallStatus::Unset,
        }
    }

    pub fn none() -> ApiCallResult {
        ApiCallResult {
            rc: None,
            output: None,
            status: ApiCallStatus::None,
        }
    }

    pub fn from(rc: Option<i32>, output: Option<String>, status: ApiCallStatus) -> ApiCallResult {
        ApiCallResult { rc, output, status }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApiCallStatus {
    Unset,
    None,
    ChangeSuccessful(String),
    Failure(String),
    AllowedFailure(String),
}
