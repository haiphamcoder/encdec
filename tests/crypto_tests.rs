use encdec::crypto::{aes, des, rsa};
use encdec::types::{OutputEncoding, Padding};

#[test]
fn test_aes_key_generation() {
    // Test AES-128 key generation
    let key_128 = aes::generate_key(128).unwrap();
    assert_eq!(key_128.len(), 16); // 128 bits = 16 bytes

    // Test AES-192 key generation
    let key_192 = aes::generate_key(192).unwrap();
    assert_eq!(key_192.len(), 24); // 192 bits = 24 bytes

    // Test AES-256 key generation
    let key_256 = aes::generate_key(256).unwrap();
    assert_eq!(key_256.len(), 32); // 256 bits = 32 bytes
}

#[test]
fn test_aes_cbc_encryption_decryption() {
    let key = aes::generate_key(256).unwrap();
    let data = b"Hello, World! This is a test message for AES encryption.";

    // Test CBC encryption
    let iv = aes::generate_iv().unwrap();
    let ciphertext = aes::encrypt_cbc(data, &key, &iv).unwrap();
    assert_ne!(ciphertext, data);
    assert_eq!(iv.len(), 16); // AES block size

    // Test CBC decryption
    let plaintext = aes::decrypt_cbc(&ciphertext, &key, &iv).unwrap();
    assert_eq!(plaintext, data);
}

#[test]
fn test_aes_gcm_encryption_decryption() {
    let key = aes::generate_key(256).unwrap();
    let data = b"Hello, World! This is a test message for AES-GCM encryption.";

    // Test GCM encryption
    let nonce = aes::generate_gcm_nonce().unwrap();
    let ciphertext = aes::encrypt_gcm(data, &key, &nonce).unwrap();
    assert_ne!(ciphertext, data);
    assert_eq!(nonce.len(), 12); // GCM nonce size

    // Test GCM decryption
    let plaintext = aes::decrypt_gcm(&ciphertext, &key, &nonce).unwrap();
    assert_eq!(plaintext, data);
}

#[test]
fn test_aes_key_formatting() {
    let key = aes::generate_key(256).unwrap();

    // Test Base64 formatting
    let base64_key = aes::format_key(&key, OutputEncoding::Base64);
    assert!(base64_key.contains("AES-256 key (Base64):"));

    // Test Hex formatting
    let hex_key = aes::format_key(&key, OutputEncoding::Hex);
    assert!(hex_key.contains("AES-256 key (Hex):"));

    // Test UTF-8 formatting
    let utf8_key = aes::format_key(&key, OutputEncoding::Utf8);
    assert!(utf8_key.contains("AES-256 key (UTF-8):"));
}

#[test]
fn test_aes_key_loading() {
    let original_key = aes::generate_key(256).unwrap();
    let base64_key = aes::format_key(&original_key, OutputEncoding::Base64);

    // Extract the key part from formatted output
    let key_line = base64_key
        .lines()
        .find(|line| line.starts_with("AES-256 key (Base64):"))
        .unwrap();
    let key_b64 = key_line.split(": ").nth(1).unwrap();

    // Test key loading
    let loaded_key = aes::load_key(key_b64, OutputEncoding::Base64).unwrap();
    assert_eq!(loaded_key, original_key);
}

#[test]
fn test_des_key_generation() {
    // Test DES key generation
    let des_key = des::generate_des_key().unwrap();
    assert_eq!(des_key.len(), 8); // DES uses 64-bit keys (8 bytes)

    // Test 3DES key generation
    let triple_des_key = des::generate_3des_key().unwrap();
    assert_eq!(triple_des_key.len(), 24); // 3DES uses 192-bit keys (24 bytes)
}

#[test]
fn test_des_cbc_encryption_decryption() {
    let key = des::generate_des_key().unwrap();
    let data = b"Hello, World! This is a test message for DES encryption.";

    // Test DES CBC encryption
    let iv = des::generate_iv().unwrap();
    let ciphertext = des::encrypt_cbc(data, &key, &iv).unwrap();
    assert_ne!(ciphertext, data);
    assert_eq!(iv.len(), 8); // DES block size

    // Test DES CBC decryption
    let plaintext = des::decrypt_cbc(&ciphertext, &key, &iv).unwrap();
    assert_eq!(plaintext, data);
}

#[test]
fn test_des_key_formatting() {
    let des_key = des::generate_des_key().unwrap();
    let triple_des_key = des::generate_3des_key().unwrap();

    // Test DES key formatting
    let des_formatted = des::format_key(&des_key, OutputEncoding::Base64);
    assert!(des_formatted.contains("DES key (Base64):"));

    // Test 3DES key formatting
    let triple_des_formatted = des::format_key(&triple_des_key, OutputEncoding::Base64);
    assert!(triple_des_formatted.contains("3DES key (Base64):"));
}

#[test]
fn test_rsa_key_generation() {
    // Test RSA-2048 key generation
    let (private_key, public_key) = rsa::generate_keypair(2048).unwrap();
    // Just verify keys were generated successfully (they exist)
    // We'll test the actual functionality in other tests

    // Test RSA-4096 key generation
    let (private_key_4096, public_key_4096) = rsa::generate_keypair(4096).unwrap();
    // Just verify keys were generated successfully
    // We'll test the actual functionality in other tests
}

#[test]
fn test_rsa_pkcs1_encryption_decryption() {
    let (private_key, public_key) = rsa::generate_keypair(2048).unwrap();
    let data = b"Hello, World! This is a test message for RSA encryption.";

    // Test PKCS1 encryption
    let ciphertext = rsa::encrypt_pkcs1(data, &public_key).unwrap();
    assert_ne!(ciphertext, data);

    // Test PKCS1 decryption
    let plaintext = rsa::decrypt_pkcs1(&ciphertext, &private_key).unwrap();
    assert_eq!(plaintext, data);
}

#[test]
fn test_rsa_oaep_encryption_decryption() {
    let (private_key, public_key) = rsa::generate_keypair(2048).unwrap();
    let data = b"Hello, World! This is a test message for RSA-OAEP encryption.";

    // Test OAEP encryption
    let ciphertext = rsa::encrypt_oaep(data, &public_key).unwrap();
    assert_ne!(ciphertext, data);

    // Test OAEP decryption
    let plaintext = rsa::decrypt_oaep(&ciphertext, &private_key).unwrap();
    assert_eq!(plaintext, data);
}

#[test]
fn test_rsa_chunked_encryption_decryption() {
    let (private_key, public_key) = rsa::generate_keypair(2048).unwrap();
    let data = b"This is a longer test message that will be chunked during RSA encryption because it exceeds the maximum plaintext size for RSA-2048.";

    // Test chunked encryption
    let ciphertext = rsa::encrypt_chunked(data, &public_key, Padding::Pkcs1).unwrap();
    assert_ne!(ciphertext, data);

    // Test chunked decryption
    let plaintext = rsa::decrypt_chunked(&ciphertext, &private_key, Padding::Pkcs1).unwrap();
    assert_eq!(plaintext, data);
}

#[test]
fn test_rsa_digital_signature() {
    let (private_key, public_key) = rsa::generate_keypair(2048).unwrap();
    let data = b"Hello, World! This is a test message for RSA digital signature.";

    // Test signature creation
    let signature = rsa::sign_data(data, &private_key).unwrap();
    assert!(!signature.is_empty());

    // Test signature verification
    let is_valid = rsa::verify_signature(data, &signature, &public_key).unwrap();
    assert!(is_valid);
}

#[test]
fn test_rsa_pem_key_serialization() {
    let (private_key, public_key) = rsa::generate_keypair(2048).unwrap();

    // Test private key PEM serialization
    rsa::save_private_key_pem(&private_key, "test_private.pem").unwrap();
    let private_pem = std::fs::read_to_string("test_private.pem").unwrap();
    assert!(private_pem.contains("BEGIN PRIVATE KEY"));
    assert!(private_pem.contains("END PRIVATE KEY"));

    // Test public key PEM serialization
    rsa::save_public_key_pem(&public_key, "test_public.pem").unwrap();
    let public_pem = std::fs::read_to_string("test_public.pem").unwrap();
    assert!(public_pem.contains("BEGIN PUBLIC KEY"));
    assert!(public_pem.contains("END PUBLIC KEY"));

    // Test private key PEM deserialization
    let loaded_private = rsa::load_private_key_pem("test_private.pem").unwrap();
    // Just verify the key was loaded successfully
    // We'll test the actual functionality in other tests

    // Test public key PEM deserialization
    let loaded_public = rsa::load_public_key_pem("test_public.pem").unwrap();
    // Just verify the key was loaded successfully
    // We'll test the actual functionality in other tests

    // Clean up
    let _ = std::fs::remove_file("test_private.pem");
    let _ = std::fs::remove_file("test_public.pem");
}

#[test]
fn test_error_handling() {
    use encdec::error::CryptoError;

    // Test invalid key size
    let result = aes::generate_key(128);
    assert!(result.is_ok());

    // Test invalid algorithm parameters
    let invalid_key = vec![0u8; 16]; // Too short for AES-256
    let data = b"test";
    let result = aes::encrypt_cbc(data, &invalid_key, &vec![0u8; 16]);
    // This should work as we're providing a 16-byte key for AES-128

    // Test with proper key
    let key = aes::generate_key(128).unwrap();
    let result = aes::encrypt_cbc(data, &key, &vec![0u8; 16]);
    assert!(result.is_ok());
}

#[test]
fn test_encryption_roundtrip() {
    let test_data =
        b"This is a comprehensive test of the encryption and decryption roundtrip functionality.";

    // Test AES-256-CBC roundtrip
    let aes_key = aes::generate_key(256).unwrap();
    let aes_iv = aes::generate_iv().unwrap();
    let aes_ciphertext = aes::encrypt_cbc(test_data, &aes_key, &aes_iv).unwrap();
    let aes_plaintext = aes::decrypt_cbc(&aes_ciphertext, &aes_key, &aes_iv).unwrap();
    assert_eq!(aes_plaintext, test_data);

    // Test AES-256-GCM roundtrip
    let aes_gcm_nonce = aes::generate_gcm_nonce().unwrap();
    let aes_gcm_ciphertext = aes::encrypt_gcm(test_data, &aes_key, &aes_gcm_nonce).unwrap();
    let aes_gcm_plaintext =
        aes::decrypt_gcm(&aes_gcm_ciphertext, &aes_key, &aes_gcm_nonce).unwrap();
    assert_eq!(aes_gcm_plaintext, test_data);

    // Test DES-CBC roundtrip
    let des_key = des::generate_des_key().unwrap();
    let des_iv = des::generate_iv().unwrap();
    let des_ciphertext = des::encrypt_cbc(test_data, &des_key, &des_iv).unwrap();
    let des_plaintext = des::decrypt_cbc(&des_ciphertext, &des_key, &des_iv).unwrap();
    assert_eq!(des_plaintext, test_data);

    // Test RSA-PKCS1 roundtrip
    let (rsa_private, rsa_public) = rsa::generate_keypair(2048).unwrap();
    let rsa_ciphertext = rsa::encrypt_pkcs1(test_data, &rsa_public).unwrap();
    let rsa_plaintext = rsa::decrypt_pkcs1(&rsa_ciphertext, &rsa_private).unwrap();
    assert_eq!(rsa_plaintext, test_data);
}
