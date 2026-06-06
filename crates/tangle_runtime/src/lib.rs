#![forbid(unsafe_code)]

use core::fmt;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiErrorCode {
    InvalidRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    Internal,
}

impl ApiErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::Conflict => "conflict",
            Self::Internal => "internal_error",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::Unauthorized => 401,
            Self::Forbidden => 403,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::Internal => 500,
        }
    }
}

impl fmt::Display for ApiErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    code: ApiErrorCode,
    message: String,
}

impl ApiError {
    pub fn new(code: ApiErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::InvalidRequest, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::Unauthorized, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::Forbidden, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::NotFound, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(ApiErrorCode::Conflict, message)
    }

    pub fn internal() -> Self {
        Self::new(ApiErrorCode::Internal, "internal server error")
    }

    pub fn code(&self) -> ApiErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn http_status(&self) -> u16 {
        self.code.http_status()
    }

    pub fn envelope(&self) -> ApiErrorEnvelope {
        ApiErrorEnvelope {
            error: ApiErrorBody {
                code: self.code.as_str().to_owned(),
                message: self.message.clone(),
            },
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ApiError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorEnvelope {
    pub error: ApiErrorBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorBody {
    pub code: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::{ApiError, ApiErrorBody, ApiErrorCode, ApiErrorEnvelope};

    #[test]
    fn api_error_codes_have_stable_labels_and_statuses() {
        let cases = [
            (ApiErrorCode::InvalidRequest, "invalid_request", 400),
            (ApiErrorCode::Unauthorized, "unauthorized", 401),
            (ApiErrorCode::Forbidden, "forbidden", 403),
            (ApiErrorCode::NotFound, "not_found", 404),
            (ApiErrorCode::Conflict, "conflict", 409),
            (ApiErrorCode::Internal, "internal_error", 500),
        ];
        for (code, label, status) in cases {
            assert_eq!(code.as_str(), label);
            assert_eq!(code.to_string(), label);
            assert_eq!(code.http_status(), status);
        }
    }

    #[test]
    fn api_error_constructors_preserve_public_envelope_shape() {
        let errors = [
            ApiError::invalid_request("bad query"),
            ApiError::unauthorized("authentication required"),
            ApiError::forbidden("admin role required"),
            ApiError::not_found("listing not found"),
            ApiError::conflict("event already exists"),
            ApiError::internal(),
        ];
        assert_eq!(errors[0].http_status(), 400);
        assert_eq!(errors[1].http_status(), 401);
        assert_eq!(errors[2].http_status(), 403);
        assert_eq!(errors[3].http_status(), 404);
        assert_eq!(errors[4].http_status(), 409);
        assert_eq!(errors[5].http_status(), 500);
        assert_eq!(errors[0].code(), ApiErrorCode::InvalidRequest);
        assert_eq!(errors[0].message(), "bad query");
        assert_eq!(errors[0].to_string(), "invalid_request: bad query");
        assert_eq!(
            errors[5].envelope(),
            ApiErrorEnvelope {
                error: ApiErrorBody {
                    code: "internal_error".to_owned(),
                    message: "internal server error".to_owned()
                }
            }
        );
        assert_eq!(
            serde_json::to_value(errors[0].envelope()).expect("json"),
            serde_json::json!({
                "error": {
                    "code": "invalid_request",
                    "message": "bad query"
                }
            })
        );
        assert_eq!(
            serde_json::from_value::<ApiErrorEnvelope>(serde_json::json!({
                "error": {
                    "code": "invalid_request",
                    "message": "bad query"
                }
            }))
            .expect("envelope"),
            errors[0].envelope()
        );
    }
}
