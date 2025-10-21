//! # encdec: A Cross-Platform Cryptography CLI Utility
//! 
//! A comprehensive Rust library for cryptographic operations including symmetric encryption (AES, DES),
//! asymmetric encryption (RSA), and digital signatures.

pub mod cli;
pub mod types;
pub mod error;
pub mod util;
pub mod crypto;
pub mod streaming;

// Re-export commonly used types for easier access
pub use types::{Algorithm, Mode, Padding, OutputEncoding};
pub use error::{CryptoError, Result};
