use encdec::crypto::{aes, des, rsa};
use encdec::types::Padding;
use std::time::Instant;

#[test]
fn test_aes_performance() {
    let key = aes::generate_key(256).unwrap();
    let data = vec![0u8; 1024 * 1024]; // 1MB test data

    // Test AES-256-CBC performance
    let iv = aes::generate_iv().unwrap();
    let start = Instant::now();
    let ciphertext = aes::encrypt_cbc(&data, &key, &iv).unwrap();
    let encrypt_time = start.elapsed();

    let start = Instant::now();
    let plaintext = aes::decrypt_cbc(&ciphertext, &key, &iv).unwrap();
    let decrypt_time = start.elapsed();

    assert_eq!(plaintext, data);

    // Performance should be reasonable (less than 1 second for 1MB)
    assert!(encrypt_time.as_secs_f64() < 1.0);
    assert!(decrypt_time.as_secs_f64() < 1.0);

    println!("AES-256-CBC 1MB: Encrypt: {encrypt_time:?}, Decrypt: {decrypt_time:?}");
}

#[test]
fn test_aes_gcm_performance() {
    let key = aes::generate_key(256).unwrap();
    let data = vec![0u8; 1024 * 1024]; // 1MB test data

    // Test AES-256-GCM performance
    let nonce = aes::generate_gcm_nonce().unwrap();
    let start = Instant::now();
    let ciphertext = aes::encrypt_gcm(&data, &key, &nonce).unwrap();
    let encrypt_time = start.elapsed();

    let start = Instant::now();
    let plaintext = aes::decrypt_gcm(&ciphertext, &key, &nonce).unwrap();
    let decrypt_time = start.elapsed();

    assert_eq!(plaintext, data);

    // Performance should be reasonable (less than 1 second for 1MB)
    assert!(encrypt_time.as_secs_f64() < 1.0);
    assert!(decrypt_time.as_secs_f64() < 1.0);

    println!("AES-256-GCM 1MB: Encrypt: {encrypt_time:?}, Decrypt: {decrypt_time:?}");
}

#[test]
fn test_des_performance() {
    let key = des::generate_des_key().unwrap();
    let data = vec![0u8; 1024 * 1024]; // 1MB test data

    // Test DES-CBC performance
    let iv = des::generate_iv().unwrap();
    let start = Instant::now();
    let ciphertext = des::encrypt_cbc(&data, &key, &iv).unwrap();
    let encrypt_time = start.elapsed();

    let start = Instant::now();
    let plaintext = des::decrypt_cbc(&ciphertext, &key, &iv).unwrap();
    let decrypt_time = start.elapsed();

    assert_eq!(plaintext, data);

    // Performance should be reasonable (less than 1 second for 1MB)
    assert!(encrypt_time.as_secs_f64() < 1.0);
    assert!(decrypt_time.as_secs_f64() < 1.0);

    println!("DES-CBC 1MB: Encrypt: {encrypt_time:?}, Decrypt: {decrypt_time:?}");
}

#[test]
fn test_rsa_performance() {
    let (private_key, public_key) = rsa::generate_keypair(2048).unwrap();
    let data = b"This is a test message for RSA performance testing.";

    // Test RSA-2048 PKCS1 performance
    let start = Instant::now();
    let ciphertext = rsa::encrypt_pkcs1(data, &public_key).unwrap();
    let encrypt_time = start.elapsed();

    let start = Instant::now();
    let plaintext = rsa::decrypt_pkcs1(&ciphertext, &private_key).unwrap();
    let decrypt_time = start.elapsed();

    assert_eq!(plaintext, data);

    // RSA is slower, but should still be reasonable
    assert!(encrypt_time.as_secs_f64() < 0.1);
    assert!(decrypt_time.as_secs_f64() < 0.1);

    println!("RSA-2048 PKCS1: Encrypt: {encrypt_time:?}, Decrypt: {decrypt_time:?}");
}

#[test]
fn test_rsa_oaep_performance() {
    let (private_key, public_key) = rsa::generate_keypair(2048).unwrap();
    let data = b"This is a test message for RSA-OAEP performance testing.";

    // Test RSA-2048 OAEP performance
    let start = Instant::now();
    let ciphertext = rsa::encrypt_oaep(data, &public_key).unwrap();
    let encrypt_time = start.elapsed();

    let start = Instant::now();
    let plaintext = rsa::decrypt_oaep(&ciphertext, &private_key).unwrap();
    let decrypt_time = start.elapsed();

    assert_eq!(plaintext, data);

    // RSA is slower, but should still be reasonable
    assert!(encrypt_time.as_secs_f64() < 0.1);
    assert!(decrypt_time.as_secs_f64() < 0.1);

    println!("RSA-2048 OAEP: Encrypt: {encrypt_time:?}, Decrypt: {decrypt_time:?}");
}

#[test]
fn test_rsa_chunked_performance() {
    let (private_key, public_key) = rsa::generate_keypair(2048).unwrap();
    let data = b"This is a longer test message for RSA chunked performance testing. It needs to be long enough to require chunking for RSA-2048 encryption.";

    // Test RSA-2048 chunked performance
    let start = Instant::now();
    let ciphertext = rsa::encrypt_chunked(data, &public_key, Padding::Pkcs1).unwrap();
    let encrypt_time = start.elapsed();

    let start = Instant::now();
    let plaintext = rsa::decrypt_chunked(&ciphertext, &private_key, Padding::Pkcs1).unwrap();
    let decrypt_time = start.elapsed();

    assert_eq!(plaintext, data);

    // RSA chunked is slower, but should still be reasonable
    assert!(encrypt_time.as_secs_f64() < 0.5);
    assert!(decrypt_time.as_secs_f64() < 0.5);

    println!("RSA-2048 Chunked: Encrypt: {encrypt_time:?}, Decrypt: {decrypt_time:?}");
}

#[test]
fn test_digital_signature_performance() {
    let (private_key, public_key) = rsa::generate_keypair(2048).unwrap();
    let data = b"This is a test message for digital signature performance testing.";

    // Test signature creation performance
    let start = Instant::now();
    let signature = rsa::sign_data(data, &private_key).unwrap();
    let sign_time = start.elapsed();

    // Test signature verification performance
    let start = Instant::now();
    let is_valid = rsa::verify_signature(data, &signature, &public_key).unwrap();
    let verify_time = start.elapsed();

    assert!(is_valid);

    // Signature operations should be reasonably fast
    assert!(sign_time.as_secs_f64() < 0.1);
    assert!(verify_time.as_secs_f64() < 0.1);

    println!("RSA Digital Signature: Sign: {sign_time:?}, Verify: {verify_time:?}");
}

#[test]
fn test_large_file_simulation() {
    // Simulate processing a large file by processing multiple chunks
    let key = aes::generate_key(256).unwrap();
    let chunk_size = 64 * 1024; // 64KB chunks
    let num_chunks = 16; // Simulate 1MB total
    let total_data_size = chunk_size * num_chunks;

    let start = Instant::now();

    for i in 0..num_chunks {
        let data = vec![i as u8; chunk_size];
        let iv = aes::generate_iv().unwrap();
        let ciphertext = aes::encrypt_cbc(&data, &key, &iv).unwrap();
        let plaintext = aes::decrypt_cbc(&ciphertext, &key, &iv).unwrap();
        assert_eq!(plaintext, data);
    }

    let total_time = start.elapsed();
    let throughput = (total_data_size as f64) / total_time.as_secs_f64() / (1024.0 * 1024.0); // MB/s

    println!(
        "Large file simulation ({}MB): Total time: {:?}, Throughput: {:.2} MB/s",
        total_data_size / (1024 * 1024),
        total_time,
        throughput
    );

    // Should achieve reasonable throughput (>10 MB/s)
    assert!(throughput > 10.0);
}

#[test]
fn test_memory_usage_simulation() {
    // Test that we can process large amounts of data without excessive memory usage
    let key = aes::generate_key(256).unwrap();
    let large_data = vec![0u8; 10 * 1024 * 1024]; // 10MB

    let iv = aes::generate_iv().unwrap();
    let start = Instant::now();
    let ciphertext = aes::encrypt_cbc(&large_data, &key, &iv).unwrap();
    let encrypt_time = start.elapsed();

    let start = Instant::now();
    let plaintext = aes::decrypt_cbc(&ciphertext, &key, &iv).unwrap();
    let decrypt_time = start.elapsed();

    assert_eq!(plaintext, large_data);

    // Should complete within reasonable time
    assert!(encrypt_time.as_secs_f64() < 5.0);
    assert!(decrypt_time.as_secs_f64() < 5.0);

    let throughput = (large_data.len() as f64) / encrypt_time.as_secs_f64() / (1024.0 * 1024.0);
    println!("10MB data: Encrypt: {encrypt_time:?}, Decrypt: {decrypt_time:?}, Throughput: {throughput:.2} MB/s");
}
