use thiserror::Error;

pub type Result<T> = std::result::Result<T, CryptoError>;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Base64 decode error: {0}")]
    Base64Decode(#[from] base64::DecodeError),

    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    #[error("AEAD error")]
    Aead,

    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::errors::Error),

    #[error("PKCS#8 error: {0}")]
    Pkcs8(#[from] pkcs8::Error),

    #[error("SPKI error: {0}")]
    Spki(#[from] pkcs8::spki::Error),

    #[error("{0}")]
    Message(String),
}

impl From<&str> for CryptoError {
    fn from(value: &str) -> Self {
        CryptoError::Message(value.to_string())
    }
}

impl From<String> for CryptoError {
    fn from(value: String) -> Self {
        CryptoError::Message(value)
    }
}
