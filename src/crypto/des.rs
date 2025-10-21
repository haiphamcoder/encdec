use rand::RngCore;
use des::Des;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};

use crate::error::{CryptoError, Result};
use crate::types::{Mode, Padding, OutputEncoding};
use crate::util::{base64_encode, hex_encode, base64_decode, hex_decode};

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

pub fn load_key(key_input: &str, encoding: OutputEncoding) -> Result<Vec<u8>> {
    match encoding {
        OutputEncoding::Base64 => base64_decode(key_input),
        OutputEncoding::Hex => hex_decode(key_input),
        OutputEncoding::Utf8 => Ok(key_input.as_bytes().to_vec()),
    }
}

pub fn generate_iv() -> Result<Vec<u8>> {
    let mut iv = vec![0u8; 8]; // DES block size
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut iv);
    Ok(iv)
}

pub fn encrypt_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 8 {
        return Err(CryptoError::InvalidArgument("DES requires 8-byte key".to_string()));
    }
    
    if iv.len() != 8 {
        return Err(CryptoError::InvalidArgument("DES requires 8-byte IV".to_string()));
    }
    
    // Calculate required buffer size (data + padding)
    let block_size = 8; // DES block size
    let padded_len = ((data.len() + block_size - 1) / block_size) * block_size;
    let mut buffer = vec![0u8; padded_len];
    buffer[..data.len()].copy_from_slice(data);
    
    let cipher = Encryptor::<Des>::new_from_slices(key, iv)
        .map_err(|_| CryptoError::InvalidArgument("Invalid key or IV".to_string()))?;
    
    cipher.encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer, data.len())
        .map_err(|_| CryptoError::InvalidArgument("Encryption failed".to_string()))?;
    
    Ok(buffer)
}

pub fn decrypt_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 8 {
        return Err(CryptoError::InvalidArgument("DES requires 8-byte key".to_string()));
    }
    
    if iv.len() != 8 {
        return Err(CryptoError::InvalidArgument("DES requires 8-byte IV".to_string()));
    }
    
    let mut buffer = ciphertext.to_vec();
    let cipher = Decryptor::<Des>::new_from_slices(key, iv)
        .map_err(|_| CryptoError::InvalidArgument("Invalid key or IV".to_string()))?;
    
    let plaintext = cipher.decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|_| CryptoError::Message("Decryption failed - invalid ciphertext or key".to_string()))?;
    
    Ok(plaintext.to_vec())
}

pub fn encrypt(data: &[u8], key: &[u8], mode: Mode, _padding: Padding) -> Result<(Vec<u8>, Vec<u8>)> {
    match mode {
        Mode::Cbc => {
            let iv = generate_iv()?;
            let ciphertext = encrypt_cbc(data, key, &iv)?;
            Ok((ciphertext, iv))
        }
        _ => Err(CryptoError::InvalidArgument(format!("DES mode {:?} not yet implemented", mode))),
    }
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], mode: Mode, _padding: Padding, iv: &[u8]) -> Result<Vec<u8>> {
    match mode {
        Mode::Cbc => decrypt_cbc(ciphertext, key, iv),
        _ => Err(CryptoError::InvalidArgument(format!("DES mode {:?} not yet implemented", mode))),
    }
}
