use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn test_keygen_aes_commands() {
    // Test AES-256 key generation
    let output = Command::new("cargo")
        .args(["run", "--", "keygen", "--alg", "aes", "--size", "256"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AES-256 key (Base64):"));

    // Test AES-128 key generation with hex output
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "keygen",
            "--alg",
            "aes",
            "--size",
            "128",
            "--output-encoding",
            "hex",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AES-128 key (Hex):"));
}

#[test]
fn test_keygen_des_commands() {
    // Test DES key generation
    let output = Command::new("cargo")
        .args(["run", "--", "keygen", "--alg", "des", "--size", "64"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DES/3DES key (Base64):"));
}

#[test]
fn test_keygen_rsa_commands() {
    // Test RSA-2048 key generation
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "keygen",
            "--alg",
            "rsa",
            "--size",
            "2048",
            "--private-out",
            "test_private.pem",
            "--public-out",
            "test_public.pem",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());

    // Verify files were created
    assert!(Path::new("test_private.pem").exists());
    assert!(Path::new("test_public.pem").exists());

    // Clean up
    let _ = fs::remove_file("test_private.pem");
    let _ = fs::remove_file("test_public.pem");
}

#[test]
fn test_encrypt_decrypt_aes_workflow() {
    // Create test file
    let test_data = "This is a test message for encryption and decryption workflow.";
    fs::write("test_input.txt", test_data).expect("Failed to write test file");

    // Generate AES key
    let key_output = Command::new("cargo")
        .args(["run", "--", "keygen", "--alg", "aes", "--size", "256"])
        .output()
        .expect("Failed to generate key");

    assert!(key_output.status.success());
    let key_stdout = String::from_utf8_lossy(&key_output.stdout);
    let key_line = key_stdout
        .lines()
        .find(|line| line.starts_with("AES-256 key (Base64):"))
        .unwrap();
    let key_b64 = key_line.split(": ").nth(1).unwrap();

    // Encrypt file
    let encrypt_output = Command::new("cargo")
        .args([
            "run",
            "--",
            "encrypt",
            "--alg",
            "aes",
            "--mode",
            "cbc",
            "--key",
            key_b64,
            "--input-file",
            "test_input.txt",
            "--output-file",
            "test_encrypted.bin",
        ])
        .output()
        .expect("Failed to encrypt");

    assert!(encrypt_output.status.success());
    assert!(Path::new("test_encrypted.bin").exists());

    // Decrypt file
    let decrypt_output = Command::new("cargo")
        .args([
            "run",
            "--",
            "decrypt",
            "--alg",
            "aes",
            "--mode",
            "cbc",
            "--key",
            key_b64,
            "--input-file",
            "test_encrypted.bin",
            "--output-file",
            "test_decrypted.txt",
        ])
        .output()
        .expect("Failed to decrypt");

    assert!(decrypt_output.status.success());
    assert!(Path::new("test_decrypted.txt").exists());

    // Verify decrypted content
    let decrypted_data =
        fs::read_to_string("test_decrypted.txt").expect("Failed to read decrypted file");
    assert_eq!(decrypted_data, test_data);

    // Clean up
    let _ = fs::remove_file("test_input.txt");
    let _ = fs::remove_file("test_encrypted.bin");
    let _ = fs::remove_file("test_decrypted.txt");
}

#[test]
fn test_encrypt_decrypt_rsa_workflow() {
    // Create test file
    let test_data = "This is a test message for RSA encryption and decryption workflow.";
    fs::write("test_rsa_input.txt", test_data).expect("Failed to write test file");

    // Generate RSA key pair
    let keygen_output = Command::new("cargo")
        .args([
            "run",
            "--",
            "keygen",
            "--alg",
            "rsa",
            "--size",
            "2048",
            "--private-out",
            "rsa_private.pem",
            "--public-out",
            "rsa_public.pem",
        ])
        .output()
        .expect("Failed to generate RSA keys");

    assert!(keygen_output.status.success());

    // Encrypt with public key
    let encrypt_output = Command::new("cargo")
        .args([
            "run",
            "--",
            "encrypt",
            "--alg",
            "rsa",
            "--public-key",
            "rsa_public.pem",
            "--input-file",
            "test_rsa_input.txt",
            "--output-file",
            "test_rsa_encrypted.bin",
        ])
        .output()
        .expect("Failed to encrypt with RSA");

    assert!(encrypt_output.status.success());
    assert!(Path::new("test_rsa_encrypted.bin").exists());

    // Decrypt with private key
    let decrypt_output = Command::new("cargo")
        .args([
            "run",
            "--",
            "decrypt",
            "--alg",
            "rsa",
            "--private-key",
            "rsa_private.pem",
            "--input-file",
            "test_rsa_encrypted.bin",
            "--output-file",
            "test_rsa_decrypted.txt",
        ])
        .output()
        .expect("Failed to decrypt with RSA");

    assert!(decrypt_output.status.success());
    assert!(Path::new("test_rsa_decrypted.txt").exists());

    // Verify decrypted content
    let decrypted_data =
        fs::read_to_string("test_rsa_decrypted.txt").expect("Failed to read decrypted file");
    assert_eq!(decrypted_data, test_data);

    // Clean up
    let _ = fs::remove_file("test_rsa_input.txt");
    let _ = fs::remove_file("test_rsa_encrypted.bin");
    let _ = fs::remove_file("test_rsa_decrypted.txt");
    let _ = fs::remove_file("rsa_private.pem");
    let _ = fs::remove_file("rsa_public.pem");
}

#[test]
fn test_sign_verify_workflow() {
    // Create test file
    let test_data = "This is a test message for digital signature workflow.";
    fs::write("test_sign_input.txt", test_data).expect("Failed to write test file");

    // Generate RSA key pair
    let keygen_output = Command::new("cargo")
        .args([
            "run",
            "--",
            "keygen",
            "--alg",
            "rsa",
            "--size",
            "2048",
            "--private-out",
            "sign_private.pem",
            "--public-out",
            "sign_public.pem",
        ])
        .output()
        .expect("Failed to generate RSA keys");

    assert!(keygen_output.status.success());

    // Sign file
    let sign_output = Command::new("cargo")
        .args([
            "run",
            "--",
            "sign",
            "--alg",
            "rsa",
            "--private-key",
            "sign_private.pem",
            "--input-file",
            "test_sign_input.txt",
            "--output-sig",
            "test_signature.sig",
        ])
        .output()
        .expect("Failed to sign file");

    assert!(sign_output.status.success());
    assert!(Path::new("test_signature.sig").exists());

    // Verify signature
    let verify_output = Command::new("cargo")
        .args([
            "run",
            "--",
            "verify",
            "--alg",
            "rsa",
            "--public-key",
            "sign_public.pem",
            "--input-file",
            "test_sign_input.txt",
            "--signature",
            "test_signature.sig",
        ])
        .output()
        .expect("Failed to verify signature");

    assert!(verify_output.status.success());
    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(verify_stdout.contains("Signature is valid"));

    // Clean up
    let _ = fs::remove_file("test_sign_input.txt");
    let _ = fs::remove_file("test_signature.sig");
    let _ = fs::remove_file("sign_private.pem");
    let _ = fs::remove_file("sign_public.pem");
}

#[test]
fn test_streaming_encryption_workflow() {
    // Create a larger test file
    let test_data = "This is a test message for streaming encryption workflow. ".repeat(1000);
    fs::write("test_streaming_input.txt", &test_data).expect("Failed to write test file");

    // Generate AES key
    let key_output = Command::new("cargo")
        .args(["run", "--", "keygen", "--alg", "aes", "--size", "256"])
        .output()
        .expect("Failed to generate key");

    assert!(key_output.status.success());
    let key_stdout = String::from_utf8_lossy(&key_output.stdout);
    let key_line = key_stdout
        .lines()
        .find(|line| line.starts_with("AES-256 key (Base64):"))
        .unwrap();
    let key_b64 = key_line.split(": ").nth(1).unwrap();

    // Encrypt with streaming
    let encrypt_output = Command::new("cargo")
        .args([
            "run",
            "--",
            "encrypt",
            "--alg",
            "aes",
            "--mode",
            "cbc",
            "--key",
            key_b64,
            "--input-file",
            "test_streaming_input.txt",
            "--output-file",
            "test_streaming_encrypted.bin",
            "--stream",
        ])
        .output()
        .expect("Failed to encrypt with streaming");

    if !encrypt_output.status.success() {
        println!("Encrypt failed with status: {:?}", encrypt_output.status);
        println!(
            "Stderr: {}",
            String::from_utf8_lossy(&encrypt_output.stderr)
        );
        println!(
            "Stdout: {}",
            String::from_utf8_lossy(&encrypt_output.stdout)
        );
    }
    assert!(encrypt_output.status.success());
    assert!(Path::new("test_streaming_encrypted.bin").exists());

    // Decrypt with streaming
    let decrypt_output = Command::new("cargo")
        .args([
            "run",
            "--",
            "decrypt",
            "--alg",
            "aes",
            "--mode",
            "cbc",
            "--key",
            key_b64,
            "--input-file",
            "test_streaming_encrypted.bin",
            "--output-file",
            "test_streaming_decrypted.txt",
            "--stream",
        ])
        .output()
        .expect("Failed to decrypt with streaming");

    assert!(decrypt_output.status.success());
    assert!(Path::new("test_streaming_decrypted.txt").exists());

    // Verify decrypted content
    let decrypted_data =
        fs::read_to_string("test_streaming_decrypted.txt").expect("Failed to read decrypted file");
    assert_eq!(decrypted_data, test_data);

    // Clean up
    let _ = fs::remove_file("test_streaming_input.txt");
    let _ = fs::remove_file("test_streaming_encrypted.bin");
    let _ = fs::remove_file("test_streaming_decrypted.txt");
}

#[test]
fn test_error_handling() {
    // Test missing key error
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "encrypt",
            "--alg",
            "aes",
            "--input-data",
            "test data",
            "--output-file",
            "output.txt",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Must provide either --key or --key-file"));

    // Test invalid algorithm for signing
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "sign",
            "--alg",
            "aes",
            "--private-key",
            "key.pem",
            "--input-file",
            "test.txt",
            "--output-sig",
            "sig.sig",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Sign currently supports RSA only"));
}

#[test]
fn test_help_commands() {
    // Test main help
    let output = Command::new("cargo")
        .args(["run", "--", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("encdec"));
    assert!(stdout.contains("command-line tool"));

    // Test encrypt help
    let output = Command::new("cargo")
        .args(["run", "--", "encrypt", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Encrypt data using various cryptographic algorithms"));
    assert!(stdout.contains("--stream"));
}

#[test]
fn test_different_encodings() {
    // Test Base64 encoding
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "keygen",
            "--alg",
            "aes",
            "--size",
            "256",
            "--output-encoding",
            "base64",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AES-256 key (Base64):"));

    // Test Hex encoding
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "keygen",
            "--alg",
            "aes",
            "--size",
            "256",
            "--output-encoding",
            "hex",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AES-256 key (Hex):"));

    // Test UTF-8 encoding
    let output = Command::new("cargo")
        .args([
            "run",
            "--",
            "keygen",
            "--alg",
            "aes",
            "--size",
            "256",
            "--output-encoding",
            "utf8",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AES-256 key (Utf8):"));
}
