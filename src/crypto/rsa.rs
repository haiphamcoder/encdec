use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::oaep::Oaep;
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use pkcs8::{EncodePrivateKey, EncodePublicKey, DecodePrivateKey, DecodePublicKey};
use sha2::Sha256;

use crate::error::{CryptoError, Result};
use crate::types::Padding;
use crate::util::{write_bytes_to_file, invalid_arg};

pub fn generate_keypair(bits: u32) -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = OsRng;
    
    let private_key = RsaPrivateKey::new(&mut rng, bits as usize)
        .map_err(|e| CryptoError::Rsa(e))?;
    
    let public_key = RsaPublicKey::from(&private_key);
    
    Ok((private_key, public_key))
}

pub fn save_private_key_pem(private_key: &RsaPrivateKey, path: &str) -> Result<()> {
    let pem = private_key.to_pkcs8_pem(pkcs8::LineEnding::LF)
        .map_err(|e| CryptoError::Pkcs8(e))?;
    
    write_bytes_to_file(path, pem.as_bytes())?;
    Ok(())
}

pub fn save_public_key_pem(public_key: &RsaPublicKey, path: &str) -> Result<()> {
    let pem = public_key.to_public_key_pem(pkcs8::LineEnding::LF)
        .map_err(|e| CryptoError::Spki(e))?;
    
    write_bytes_to_file(path, pem.as_bytes())?;
    Ok(())
}

pub fn load_private_key_pem(path: &str) -> Result<RsaPrivateKey> {
    let pem_data = std::fs::read(path)?;
    let pem_str = String::from_utf8(pem_data)
        .map_err(|_| CryptoError::InvalidArgument("Invalid PEM file encoding".to_string()))?;
    
    RsaPrivateKey::from_pkcs8_pem(&pem_str)
        .map_err(|e| CryptoError::Pkcs8(e))
}

pub fn load_public_key_pem(path: &str) -> Result<RsaPublicKey> {
    let pem_data = std::fs::read(path)?;
    let pem_str = String::from_utf8(pem_data)
        .map_err(|_| CryptoError::InvalidArgument("Invalid PEM file encoding".to_string()))?;
    
    RsaPublicKey::from_public_key_pem(&pem_str)
        .map_err(|e| CryptoError::Spki(e))
}

pub fn encrypt_pkcs1(data: &[u8], public_key: &RsaPublicKey) -> Result<Vec<u8>> {
    let mut rng = OsRng;
    let padding = Pkcs1v15Encrypt;
    
    public_key.encrypt(&mut rng, padding, data)
        .map_err(|e| CryptoError::Rsa(e))
}

pub fn decrypt_pkcs1(ciphertext: &[u8], private_key: &RsaPrivateKey) -> Result<Vec<u8>> {
    let padding = Pkcs1v15Encrypt;
    
    private_key.decrypt(padding, ciphertext)
        .map_err(|e| CryptoError::Rsa(e))
}

pub fn encrypt_oaep(data: &[u8], public_key: &RsaPublicKey) -> Result<Vec<u8>> {
    let mut rng = OsRng;
    let padding = Oaep::new::<Sha256>();
    
    public_key.encrypt(&mut rng, padding, data)
        .map_err(|e| CryptoError::Rsa(e))
}

pub fn decrypt_oaep(ciphertext: &[u8], private_key: &RsaPrivateKey) -> Result<Vec<u8>> {
    let padding = Oaep::new::<Sha256>();
    
    private_key.decrypt(padding, ciphertext)
        .map_err(|e| CryptoError::Rsa(e))
}

pub fn encrypt(data: &[u8], public_key: &RsaPublicKey, padding: Padding) -> Result<Vec<u8>> {
    match padding {
        Padding::Pkcs1 => encrypt_pkcs1(data, public_key),
        Padding::OaepSha256 => encrypt_oaep(data, public_key),
        _ => Err(CryptoError::InvalidArgument(format!("RSA padding {:?} not supported", padding))),
    }
}

pub fn decrypt(ciphertext: &[u8], private_key: &RsaPrivateKey, padding: Padding) -> Result<Vec<u8>> {
    match padding {
        Padding::Pkcs1 => decrypt_pkcs1(ciphertext, private_key),
        Padding::OaepSha256 => decrypt_oaep(ciphertext, private_key),
        _ => Err(CryptoError::InvalidArgument(format!("RSA padding {:?} not supported", padding))),
    }
}

pub fn get_max_plaintext_size(public_key: &RsaPublicKey, padding: Padding) -> usize {
    let key_size = public_key.size();
    match padding {
        Padding::Pkcs1 => key_size - 11, // PKCS1 padding overhead
        Padding::OaepSha256 => key_size - 42, // OAEP-SHA256 padding overhead
        _ => 0,
    }
}

pub fn chunk_data(data: &[u8], chunk_size: usize) -> Vec<&[u8]> {
    data.chunks(chunk_size).collect()
}

pub fn encrypt_chunked(data: &[u8], public_key: &RsaPublicKey, padding: Padding) -> Result<Vec<u8>> {
    let max_chunk_size = get_max_plaintext_size(public_key, padding);
    if max_chunk_size == 0 {
        return Err(CryptoError::InvalidArgument("Invalid padding for RSA encryption".to_string()));
    }
    
    let chunks = chunk_data(data, max_chunk_size);
    let mut encrypted_data = Vec::new();
    
    for chunk in chunks {
        let encrypted_chunk = encrypt(chunk, public_key, padding)?;
        // Prepend chunk length (4 bytes) to each encrypted chunk
        let chunk_len = (encrypted_chunk.len() as u32).to_be_bytes();
        encrypted_data.extend_from_slice(&chunk_len);
        encrypted_data.extend_from_slice(&encrypted_chunk);
    }
    
    Ok(encrypted_data)
}

pub fn decrypt_chunked(encrypted_data: &[u8], private_key: &RsaPrivateKey, padding: Padding) -> Result<Vec<u8>> {
    let mut decrypted_data = Vec::new();
    let mut offset = 0;
    
    while offset < encrypted_data.len() {
        if offset + 4 > encrypted_data.len() {
            return Err(CryptoError::InvalidArgument("Invalid chunked data format".to_string()));
        }
        
        // Read chunk length
        let chunk_len = u32::from_be_bytes([
            encrypted_data[offset],
            encrypted_data[offset + 1],
            encrypted_data[offset + 2],
            encrypted_data[offset + 3],
        ]) as usize;
        
        offset += 4;
        
        if offset + chunk_len > encrypted_data.len() {
            return Err(CryptoError::InvalidArgument("Invalid chunked data format".to_string()));
        }
        
        // Decrypt chunk
        let chunk_data = &encrypted_data[offset..offset + chunk_len];
        let decrypted_chunk = decrypt(chunk_data, private_key, padding)?;
        decrypted_data.extend_from_slice(&decrypted_chunk);
        
        offset += chunk_len;
    }
    
    Ok(decrypted_data)
}

pub fn validate_rsa_key_size(size: u32) -> Result<()> {
    match size {
        2048 | 3072 | 4096 => Ok(()),
        _ => invalid_arg(format!("RSA key size must be 2048, 3072, or 4096 bits, got {}", size)),
    }
}
