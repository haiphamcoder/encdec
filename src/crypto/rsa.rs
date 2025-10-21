use rsa::{RsaPrivateKey, RsaPublicKey};
use pkcs8::{EncodePrivateKey, EncodePublicKey};

use crate::error::Result;
use crate::util::{write_bytes_to_file, invalid_arg};

pub fn generate_keypair(bits: u32) -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = rand::thread_rng();
    
    let private_key = RsaPrivateKey::new(&mut rng, bits as usize)
        .map_err(|e| crate::error::CryptoError::Rsa(e))?;
    
    let public_key = RsaPublicKey::from(&private_key);
    
    Ok((private_key, public_key))
}

pub fn save_private_key_pem(private_key: &RsaPrivateKey, path: &str) -> Result<()> {
    let pem = private_key.to_pkcs8_pem(pkcs8::LineEnding::LF)
        .map_err(|e| crate::error::CryptoError::Pkcs8(e))?;
    
    write_bytes_to_file(path, pem.as_bytes())?;
    Ok(())
}

pub fn save_public_key_pem(public_key: &RsaPublicKey, path: &str) -> Result<()> {
    let pem = public_key.to_public_key_pem(pkcs8::LineEnding::LF)
        .map_err(|e| crate::error::CryptoError::Spki(e))?;
    
    write_bytes_to_file(path, pem.as_bytes())?;
    Ok(())
}

pub fn validate_rsa_key_size(size: u32) -> Result<()> {
    match size {
        2048 | 3072 | 4096 => Ok(()),
        _ => invalid_arg(format!("RSA key size must be 2048, 3072, or 4096 bits, got {}", size)),
    }
}
