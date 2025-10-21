use rand::RngCore;

use crate::error::Result;
use crate::types::OutputEncoding;
use crate::util::{base64_encode, hex_encode};

pub fn generate_des_key() -> Result<Vec<u8>> {
    let mut key = vec![0u8; 8]; // DES uses 64-bit keys (8 bytes)
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut key);
    Ok(key)
}

pub fn generate_3des_key() -> Result<Vec<u8>> {
    let mut key = vec![0u8; 24]; // 3DES uses 192-bit keys (24 bytes)
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut key);
    Ok(key)
}

pub fn format_key(key: &[u8], encoding: OutputEncoding) -> String {
    match encoding {
        OutputEncoding::Base64 => base64_encode(key),
        OutputEncoding::Hex => hex_encode(key),
        OutputEncoding::Utf8 => {
            // For display purposes, show as hex even for UTF8
            hex_encode(key)
        }
    }
}
