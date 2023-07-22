use thiserror::Error;

pub type AResult<T> = Result<T, AuthError>;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("base64 decode err: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("php_serde err: {0}")]
    PhpSerde(#[from] php_serde::Error),
    #[error("serde_json err: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("aes unpad err {0}")]
    AesUnpadError(#[from] aes::cipher::block_padding::UnpadError),
    #[error("utf8 err {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("missing session id")]
    MissingSessionId,
    #[error("dotenv err {0}")]
    Dotenv(#[from] dotenv::Error),
    #[error("io err {0}")]
    Io(#[from] std::io::Error),
}
