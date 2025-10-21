//! # encdec: A Cross-Platform Cryptography CLI Utility
//!
//! A comprehensive Rust library for cryptographic operations including symmetric encryption (AES, DES),
//! asymmetric encryption (RSA), and digital signatures.

pub mod cli;
pub mod crypto;
pub mod error;
pub mod streaming;
pub mod types;
pub mod util;

// Re-export commonly used types for easier access
pub use error::{CryptoError, Result};
pub use types::{Algorithm, Mode, OutputEncoding, Padding};
