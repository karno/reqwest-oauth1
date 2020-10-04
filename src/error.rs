use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;
pub type SignResult<T> = std::result::Result<T, SignError>;
pub type TokenReaderResult<T> = std::result::Result<T, TokenReaderError>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("token acquisition failed : {0}")]
    TokenReader(#[from] TokenReaderError),
    #[error("OAuth sign failed : {0}")]
    Signer(#[from] SignError),
    #[error("request failed : {0}")]
    Reqwest(#[from] reqwest::Error),
}

#[derive(Error, Debug, Clone)]
pub enum SignError {
    #[error("unknown oauth parameter : {0}")]
    UnknownParameter(String),
    #[error("specified parameter {0} could not be configured via the reqwest parameters.")]
    UnconfigurableParameter(String),
    #[error("invalid oauth_timestamp, must be u64, but {0} is not compatible.")]
    InvalidTimestamp(String),
    #[error("invalid oauth_version, must be 1.0 or just empty, but specified {0}.")]
    InvalidVersion(String),
}

#[derive(Error, Debug, Clone)]
pub enum TokenReaderError {
    #[error("response has malformed format: not found {0} in {1}")]
    TokenKeyNotFound(&'static str, String),
}
