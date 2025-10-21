use rand::RngCore;

use crate::error::Result;
use crate::types::OutputEncoding;
use crate::util::{base64_encode, hex_encode};

pub fn generate_key(size_bits: u32) -> Result<Vec<u8>> {
    let size_bytes = (size_bits / 8) as usize;
    let mut key = vec![0u8; size_bytes];
    
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut key);
    
    Ok(key)
}

pub fn generate_key_with_password(password: &str, salt: &[u8], size_bits: u32) -> Result<Vec<u8>> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;
    
    let size_bytes = (size_bits / 8) as usize;
    let mut key = vec![0u8; size_bytes];
    
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, 100_000, &mut key);
    
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

pub fn generate_random_salt() -> Result<Vec<u8>> {
    let mut salt = vec![0u8; 16];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    Ok(salt)
}
