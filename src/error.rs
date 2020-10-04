use thiserror::Error;

/// Result type bound with `Error`.
pub type Result<T> = std::result::Result<T, Error>;
/// Result type bound with `SignError`.
pub type SignResult<T> = std::result::Result<T, SignError>;
/// Result type bound with `TokenReaderError`.
pub type TokenReaderResult<T> = std::result::Result<T, TokenReaderError>;

/// The Error bundles the TokenReaderError, SignError, and reqwest::Error.
#[derive(Error, Debug)]
pub enum Error {
    #[error("token acquisition failed : {0}")]
    TokenReader(#[from] TokenReaderError),
    #[error("OAuth sign failed : {0}")]
    Signer(#[from] SignError),
    #[error("request failed : {0}")]
    Reqwest(#[from] reqwest::Error),
}

/// Errors about the signing with OAuth1 protocol.
#[derive(Error, Debug, Clone)]
pub enum SignError {
    /// Specified oauth_* parameter is not existed in the protocol specification.
    #[error("unknown oauth parameter : {0}")]
    UnknownParameter(String),
    /// Specified oauth_* parameter is not configured via the reqwest::RequestBuilder::(query/form).
    #[error("specified parameter {0} could not be configured via the reqwest parameters.")]
    UnconfigurableParameter(String),
    /// An invalid value is specified as the oauth_timestamp parameter.
    #[error("invalid oauth_timestamp, must be u64, but {0} is not compatible.")]
    InvalidTimestamp(String),
    /// An invalid value is specified as the oauth_version parameter.
    #[error("invalid oauth_version, must be 1.0 or just empty, but specified {0}.")]
    InvalidVersion(String),
}

/// Errors thrown from token_reader.
#[derive(Error, Debug, Clone)]
pub enum TokenReaderError {
    /// Returned value could not be parsed in the TokenReader.
    #[error("the response has malformed format: key {0} is not found in response {1}")]
    TokenKeyNotFound(&'static str, String),
}
