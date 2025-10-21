use rand::RngCore;
use aes::Aes256;
use aes_gcm::{Aes256Gcm, KeyInit};
use aes_gcm::aead::Aead;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit};

use crate::error::{CryptoError, Result};
use crate::types::{Mode, Padding, OutputEncoding};
use crate::util::{base64_encode, hex_encode, base64_decode, hex_decode};
use crate::streaming::StreamingWriter;

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

pub fn generate_iv() -> Result<Vec<u8>> {
    let mut iv = vec![0u8; 16]; // AES block size
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut iv);
    Ok(iv)
}

pub fn load_key(key_input: &str, encoding: OutputEncoding) -> Result<Vec<u8>> {
    match encoding {
        OutputEncoding::Base64 => base64_decode(key_input),
        OutputEncoding::Hex => hex_decode(key_input),
        OutputEncoding::Utf8 => Ok(key_input.as_bytes().to_vec()),
    }
}

pub fn encrypt_cbc(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidArgument("AES-256 requires 32-byte key".to_string()));
    }
    
    if iv.len() != 16 {
        return Err(CryptoError::InvalidArgument("AES requires 16-byte IV".to_string()));
    }
    
    // Calculate required buffer size (data + padding)
    let block_size = 16; // AES block size
    let padded_len = ((data.len() + block_size - 1) / block_size) * block_size;
    let mut buffer = vec![0u8; padded_len];
    buffer[..data.len()].copy_from_slice(data);
    
    let cipher = Encryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| CryptoError::InvalidArgument("Invalid key or IV".to_string()))?;
    
    cipher.encrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer, data.len())
        .map_err(|_| CryptoError::InvalidArgument("Encryption failed".to_string()))?;
    
    Ok(buffer)
}

pub fn decrypt_cbc(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidArgument("AES-256 requires 32-byte key".to_string()));
    }
    
    if iv.len() != 16 {
        return Err(CryptoError::InvalidArgument("AES requires 16-byte IV".to_string()));
    }
    
    let mut buffer = ciphertext.to_vec();
    let cipher = Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| CryptoError::InvalidArgument("Invalid key or IV".to_string()))?;
    
    let plaintext = cipher.decrypt_padded_mut::<cbc::cipher::block_padding::Pkcs7>(&mut buffer)
        .map_err(|_| CryptoError::Message("Decryption failed - invalid ciphertext or key".to_string()))?;
    
    Ok(plaintext.to_vec())
}

pub fn encrypt_gcm(data: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidArgument("AES-256-GCM requires 32-byte key".to_string()));
    }
    
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidArgument("AES-GCM requires 12-byte nonce".to_string()));
    }
    
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| CryptoError::InvalidArgument("Invalid key length".to_string()))?;
    let nonce_array: [u8; 12] = nonce.try_into()
        .map_err(|_| CryptoError::InvalidArgument("Invalid nonce length".to_string()))?;
    
    let cipher = Aes256Gcm::new(&key_array.into());
    let nonce = &nonce_array.into();
    
    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|_| CryptoError::Aead)?;
    
    Ok(ciphertext)
}

pub fn decrypt_gcm(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(CryptoError::InvalidArgument("AES-256-GCM requires 32-byte key".to_string()));
    }
    
    if nonce.len() != 12 {
        return Err(CryptoError::InvalidArgument("AES-GCM requires 12-byte nonce".to_string()));
    }
    
    let key_array: [u8; 32] = key.try_into()
        .map_err(|_| CryptoError::InvalidArgument("Invalid key length".to_string()))?;
    let nonce_array: [u8; 12] = nonce.try_into()
        .map_err(|_| CryptoError::InvalidArgument("Invalid nonce length".to_string()))?;
    
    let cipher = Aes256Gcm::new(&key_array.into());
    let nonce = &nonce_array.into();
    
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| CryptoError::Aead)?;
    
    Ok(plaintext)
}

pub fn encrypt_file_streaming(
    input_path: &str,
    output_path: &str,
    key: &[u8],
    mode: Mode,
    padding: Padding,
) -> Result<u64> {
    let file_size = std::fs::metadata(input_path)?.len();
    
    match mode {
        Mode::Cbc => {
            // For CBC streaming, we need to handle the entire file as one operation
            // because CBC requires the previous block's ciphertext for the next block
            let data = std::fs::read(input_path)?;
            let iv = generate_iv()?;
            let ciphertext = encrypt_cbc(&data, key, &iv)?;
            
            let mut writer = StreamingWriter::new_optimized(output_path, file_size)?;
            writer.write_chunk(&iv)?;
            writer.write_chunk(&ciphertext)?;
            writer.flush()?;
            
            Ok((iv.len() + ciphertext.len()) as u64)
        }
        Mode::Gcm => {
            // For GCM streaming, we need to handle the entire file as one operation
            // because GCM requires authentication of the entire message
            let data = std::fs::read(input_path)?;
            let nonce = generate_gcm_nonce()?;
            let ciphertext = encrypt_gcm(&data, key, &nonce)?;
            
            let mut writer = StreamingWriter::new_optimized(output_path, file_size)?;
            writer.write_chunk(&nonce)?;
            writer.write_chunk(&ciphertext)?;
            writer.flush()?;
            
            Ok((nonce.len() + ciphertext.len()) as u64)
        }
        _ => Err(CryptoError::InvalidArgument(format!("Streaming not supported for mode {:?}", mode))),
    }
}

pub fn decrypt_file_streaming(
    input_path: &str,
    output_path: &str,
    key: &[u8],
    mode: Mode,
    padding: Padding,
) -> Result<u64> {
    match mode {
        Mode::Cbc => {
            // For CBC streaming, we need to handle the entire file as one operation
            let data = std::fs::read(input_path)?;
            if data.len() < 16 {
                return Err(CryptoError::InvalidArgument("Invalid encrypted data format".to_string()));
            }
            
            let (iv, ciphertext) = data.split_at(16);
            let plaintext = decrypt_cbc(ciphertext, key, iv)?;
            
            let file_size = std::fs::metadata(input_path)?.len();
            let mut writer = StreamingWriter::new_optimized(output_path, file_size)?;
            writer.write_chunk(&plaintext)?;
            writer.flush()?;
            
            Ok(plaintext.len() as u64)
        }
        Mode::Gcm => {
            // For GCM streaming, we need to handle the entire file as one operation
            let data = std::fs::read(input_path)?;
            if data.len() < 12 {
                return Err(CryptoError::InvalidArgument("Invalid encrypted data format".to_string()));
            }
            
            let (nonce, ciphertext) = data.split_at(12);
            let plaintext = decrypt_gcm(ciphertext, key, nonce)?;
            
            let file_size = std::fs::metadata(input_path)?.len();
            let mut writer = StreamingWriter::new_optimized(output_path, file_size)?;
            writer.write_chunk(&plaintext)?;
            writer.flush()?;
            
            Ok(plaintext.len() as u64)
        }
        _ => Err(CryptoError::InvalidArgument(format!("Streaming not supported for mode {:?}", mode))),
    }
}

pub fn generate_gcm_nonce() -> Result<Vec<u8>> {
    let mut nonce = vec![0u8; 12]; // GCM nonce size
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut nonce);
    Ok(nonce)
}

pub fn encrypt(data: &[u8], key: &[u8], mode: Mode, _padding: Padding) -> Result<(Vec<u8>, Vec<u8>)> {
    match mode {
        Mode::Cbc => {
            let iv = generate_iv()?;
            let ciphertext = encrypt_cbc(data, key, &iv)?;
            Ok((ciphertext, iv))
        }
        Mode::Gcm => {
            let nonce = generate_gcm_nonce()?;
            let ciphertext = encrypt_gcm(data, key, &nonce)?;
            Ok((ciphertext, nonce))
        }
        _ => Err(CryptoError::InvalidArgument(format!("Mode {:?} not yet implemented", mode))),
    }
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], mode: Mode, _padding: Padding, iv_or_nonce: &[u8]) -> Result<Vec<u8>> {
    match mode {
        Mode::Cbc => decrypt_cbc(ciphertext, key, iv_or_nonce),
        Mode::Gcm => decrypt_gcm(ciphertext, key, iv_or_nonce),
        _ => Err(CryptoError::InvalidArgument(format!("Mode {:?} not yet implemented", mode))),
    }
}
