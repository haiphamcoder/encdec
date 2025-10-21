use crate::types::{Algorithm, Mode, OutputEncoding, Padding};
use crate::crypto::{aes, des, rsa};
use crate::error::{CryptoError, Result};
use crate::util::{read_input, write_output, InputSource, OutputTarget, base64_encode, hex_encode, base64_decode};
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "encdec", 
    about = "A comprehensive cryptography CLI utility for encryption, decryption, and digital signatures",
    long_about = "encdec is a powerful command-line tool that provides symmetric encryption (AES, DES), 
asymmetric encryption (RSA), and digital signature capabilities. It supports multiple encryption modes, 
padding schemes, and output formats, making it suitable for both personal and professional use.

Features:
  • Symmetric encryption: AES (128/192/256-bit) and DES/3DES
  • Asymmetric encryption: RSA (2048/3072/4096-bit)
  • Digital signatures: RSA with SHA-256
  • Multiple modes: CBC, GCM for AES; CBC for DES
  • Streaming I/O: Handle large files efficiently
  • Multiple encodings: Base64, Hex, UTF-8
  • Cross-platform: Linux, Windows, macOS

Security Warning: This tool is for educational and development purposes. 
For production use, ensure proper key management and security practices.",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Generate cryptographic keys (AES, DES, RSA)
    #[command(long_about = "Generate cryptographic keys for various algorithms:
    
    • AES: 128, 192, or 256-bit keys for symmetric encryption
    • DES: 64-bit keys for legacy symmetric encryption  
    • RSA: 2048, 3072, or 4096-bit key pairs for asymmetric encryption
    
    Keys are generated using cryptographically secure random number generation.
    Output can be formatted as Base64, Hex, or raw bytes.")]
    Keygen(KeygenArgs),
    
    /// Encrypt data or files using symmetric or asymmetric encryption
    #[command(long_about = "Encrypt data using various cryptographic algorithms:
    
    Symmetric Encryption:
    • AES: Advanced Encryption Standard with CBC or GCM modes
    • DES: Data Encryption Standard with CBC mode (legacy)
    
    Asymmetric Encryption:
    • RSA: Rivest-Shamir-Adleman with PKCS1 or OAEP padding
    
    Supports both inline data and file input/output.
    Use --stream flag for efficient processing of large files.")]
    Encrypt(CryptoArgs),
    
    /// Decrypt data or files using symmetric or asymmetric decryption
    #[command(long_about = "Decrypt data that was previously encrypted:
    
    Supports the same algorithms as encryption:
    • AES: CBC and GCM modes with proper IV/nonce handling
    • DES: CBC mode for legacy compatibility
    • RSA: PKCS1 and OAEP padding schemes
    
    Automatically detects and handles different input formats.
    Use --stream flag for efficient processing of large files.")]
    Decrypt(CryptoArgs),
    
    /// Create digital signatures for file integrity and authenticity
    #[command(long_about = "Create digital signatures using RSA with SHA-256:
    
    Digital signatures provide:
    • Data integrity: Detect if files have been modified
    • Authentication: Verify the signer's identity
    • Non-repudiation: Signer cannot deny creating the signature
    
    Requires RSA private key for signing.
    Signatures are saved as binary files for verification.")]
    Sign(SignArgs),
    
    /// Verify digital signatures to ensure file integrity and authenticity
    #[command(long_about = "Verify digital signatures created with the sign command:
    
    Verification process:
    • Loads the original file and signature
    • Uses RSA public key to verify the signature
    • Confirms file has not been tampered with
    • Validates the signer's identity
    
    Returns success/failure status for signature verification.")]
    Verify(VerifyArgs),
}

#[derive(Debug, Args)]
pub struct KeygenArgs {
    #[arg(value_enum, short = 'a', long = "alg", default_value = "aes")]
    pub algorithm: Algorithm,
    /// AES size: 128/192/256; RSA: 2048/3072/4096
    #[arg(short = 's', long = "size", default_value = "256")]
    pub size: u32,
    /// Output encoding for symmetric key material
    #[arg(value_enum, long = "output-encoding", default_value = "base64")]
    pub output_encoding: OutputEncoding,
    /// Output files for RSA keys
    #[arg(long = "private-out")]
    pub private_out: Option<String>,
    #[arg(long = "public-out")]
    pub public_out: Option<String>,
}

#[derive(Debug, Args)]
pub struct CryptoArgs {
    #[arg(value_enum, short = 'a', long = "alg", default_value = "aes")]
    pub algorithm: Algorithm,
    #[arg(value_enum, short = 'm', long = "mode", default_value = "cbc")]
    pub mode: Mode,
    #[arg(value_enum, short = 'p', long = "padding", default_value = "pkcs5")]
    pub padding: Padding,

    /// Provide key material directly (Base64, Hex, or raw)
    #[arg(long = "key", help = "Provide encryption key directly as a string. 
    Supports Base64, Hex, or raw key formats. For AES-256, provide 32 bytes (44 chars Base64).
    Mutually exclusive with --key-file.")]
    pub key: Option<String>,
    /// Read key from file (supports formatted or raw keys)
    #[arg(long = "key-file", help = "Load encryption key from a file. 
    Supports both formatted key files (generated by keygen) and raw binary key files.
    Mutually exclusive with --key.")]
    pub key_file: Option<String>,
    /// For RSA encrypt/decrypt
    #[arg(long = "public-key")]
    pub public_key: Option<String>,
    #[arg(long = "private-key")]
    pub private_key: Option<String>,

    /// Input as inline data (mutually exclusive with input-file)
    #[arg(long = "input-data")]
    pub input_data: Option<String>,
    /// Input from file
    #[arg(long = "input-file")]
    pub input_file: Option<String>,
    /// Output file (if omitted, print to stdout for string outputs)
    #[arg(long = "output-file")]
    pub output_file: Option<String>,
    /// Output encoding when printing to stdout
    #[arg(value_enum, long = "output-encoding", default_value = "base64")]
    pub output_encoding: OutputEncoding,
    /// Use streaming I/O for large files (memory efficient)
    #[arg(long = "stream", help = "Enable streaming I/O for processing large files efficiently. 
    Reduces memory usage by processing data in chunks rather than loading entire file into memory.
    Recommended for files larger than 100MB. Only works with file input/output (not inline data).")]
    pub stream: bool,
}

#[derive(Debug, Args)]
pub struct SignArgs {
    #[arg(value_enum, short = 'a', long = "alg", default_value = "rsa")]
    pub algorithm: Algorithm,
    /// Signature algorithm shorthand (e.g., sha256withrsa)
    #[arg(long = "sig-alg", default_value = "sha256withrsa")]
    pub sig_alg: String,
    #[arg(long = "private-key")]
    pub private_key: String,
    #[arg(long = "input-file")]
    pub input_file: String,
    #[arg(long = "output-sig")]
    pub output_sig: String,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    #[arg(value_enum, short = 'a', long = "alg", default_value = "rsa")]
    pub algorithm: Algorithm,
    /// Signature algorithm shorthand (e.g., sha256withrsa)
    #[arg(long = "sig-alg", default_value = "sha256withrsa")]
    pub sig_alg: String,
    #[arg(long = "public-key")]
    pub public_key: String,
    #[arg(long = "input-file")]
    pub input_file: String,
    #[arg(long = "signature")]
    pub signature: String,
}

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    
    // Print security warning for first-time users
    print_security_warning();
    
    match cli.command {
        Commands::Keygen(args) => handle_keygen(args),
        Commands::Encrypt(args) => handle_encrypt(args),
        Commands::Decrypt(args) => handle_decrypt(args),
        Commands::Sign(args) => handle_sign(args),
        Commands::Verify(args) => handle_verify(args),
    }
}

fn print_security_warning() {
    eprintln!("⚠️  SECURITY WARNING: This tool is for educational and development purposes.");
    eprintln!("   For production use, ensure proper key management and security practices.");
    eprintln!("   Never share private keys or use weak passwords in production environments.\n");
}

fn handle_keygen(args: KeygenArgs) -> Result<()> {
    match args.algorithm {
        Algorithm::Aes => {
            let key = aes::generate_key(args.size)?;
            let formatted = aes::format_key(&key, args.output_encoding);
            println!("AES-{} key ({:?}): {}", args.size, args.output_encoding, formatted);
        }
        Algorithm::Des => {
            let key = if args.size == 64 {
                des::generate_des_key()?
            } else if args.size == 192 {
                des::generate_3des_key()?
            } else {
                return Err(crate::error::CryptoError::InvalidArgument(
                    "DES key size must be 64 or 192 bits".to_string()
                ));
            };
            let formatted = des::format_key(&key, args.output_encoding);
            println!("DES/3DES key ({:?}): {}", args.output_encoding, formatted);
        }
        Algorithm::Rsa => {
            rsa::validate_rsa_key_size(args.size)?;
            let (private_key, public_key) = rsa::generate_keypair(args.size)?;
            
            if let Some(ref private_path) = args.private_out {
                rsa::save_private_key_pem(&private_key, private_path)?;
                println!("RSA private key saved to: {private_path}");
            }
            
            if let Some(ref public_path) = args.public_out {
                rsa::save_public_key_pem(&public_key, public_path)?;
                println!("RSA public key saved to: {public_path}");
            }
            
            if args.private_out.is_none() && args.public_out.is_none() {
                println!("RSA-{} key pair generated (use --private-out and --public-out to save)", args.size);
            }
        }
    }
    Ok(())
}

fn handle_encrypt(args: CryptoArgs) -> Result<()> {
    validate_input_source(&args.input_data, &args.input_file)?;
    
    // Check if we should use streaming for file operations
    if args.stream && args.input_file.is_some() && args.output_file.is_some() {
        return handle_encrypt_streaming(args);
    }
    
    // Load input data
    let input_source = if let Some(data) = &args.input_data {
        InputSource::Inline(data)
    } else {
        InputSource::File(args.input_file.as_ref().unwrap())
    };
    let data = read_input(input_source)?;
    
    // Load key (only for symmetric algorithms)
    let key = if args.algorithm == Algorithm::Rsa {
        Vec::new() // RSA doesn't use symmetric keys
    } else if let Some(key_str) = &args.key {
        load_key_from_string(key_str, args.algorithm)?
    } else if let Some(key_file) = &args.key_file {
        load_key_from_file(key_file, args.algorithm)?
    } else {
        return Err(crate::error::CryptoError::InvalidArgument(
            "Must provide either --key or --key-file for symmetric encryption. 
            For RSA encryption, use --public-key instead.".to_string()
        ));
    };
    
    // Encrypt data
    let output = match args.algorithm {
        Algorithm::Aes => {
            let (ciphertext, iv_or_nonce) = aes::encrypt(&data, &key, args.mode, args.padding)?;
            // Combine IV/nonce with ciphertext for output
            let mut output = Vec::new();
            output.extend_from_slice(&iv_or_nonce);
            output.extend_from_slice(&ciphertext);
            output
        }
        Algorithm::Des => {
            let (ciphertext, iv_or_nonce) = des::encrypt(&data, &key, args.mode, args.padding)?;
            // Combine IV/nonce with ciphertext for output
            let mut output = Vec::new();
            output.extend_from_slice(&iv_or_nonce);
            output.extend_from_slice(&ciphertext);
            output
        }
        Algorithm::Rsa => {
            // Load RSA public key
            let public_key = if let Some(key_path) = &args.public_key {
                rsa::load_public_key_pem(key_path)
                    .map_err(|e| crate::error::CryptoError::InvalidArgument(
                        format!("Failed to load RSA public key from '{key_path}': {e}")
                    ))?
            } else {
                return Err(crate::error::CryptoError::InvalidArgument(
                    "RSA encryption requires --public-key. Use 'encdec keygen --alg rsa' to generate key pairs.".to_string()
                ));
            };
            
            // Use chunked encryption for RSA (force PKCS1 padding for RSA)
            let rsa_padding = match args.padding {
                Padding::Pkcs1 | Padding::OaepSha256 => args.padding,
                _ => Padding::Pkcs1, // Default to PKCS1 for RSA
            };
            rsa::encrypt_chunked(&data, &public_key, rsa_padding)?
        }
    };
    
    // Output result
    let output_target = if let Some(file) = &args.output_file {
        OutputTarget::File(file)
    } else {
        OutputTarget::Stdout
    };
    
    if matches!(output_target, OutputTarget::Stdout) {
        let formatted = if args.algorithm == Algorithm::Rsa {
            // For RSA, always output as base64 for consistency
            base64_encode(&output)
        } else {
            format_output(&output, args.output_encoding)
        };
        println!("{formatted}");
    } else {
        if args.algorithm == Algorithm::Rsa {
            // For RSA, write base64 encoded data
            let formatted = base64_encode(&output);
            write_output(output_target, formatted.as_bytes())?;
        } else {
            // For symmetric algorithms, write raw bytes
            write_output(output_target, &output)?;
        }
        println!("Encrypted data saved to file");
    }
    
    Ok(())
}

fn handle_encrypt_streaming(args: CryptoArgs) -> Result<()> {
    // Load key (only for symmetric algorithms)
    let key = if args.algorithm == Algorithm::Rsa {
        return Err(CryptoError::InvalidArgument("Streaming not supported for RSA encryption".to_string()));
    } else if let Some(key_str) = &args.key {
        load_key_from_string(key_str, args.algorithm)?
    } else if let Some(key_file) = &args.key_file {
        load_key_from_file(key_file, args.algorithm)?
    } else {
        return Err(CryptoError::InvalidArgument("Must provide either --key or --key-file".to_string()));
    };
    
    let input_file = args.input_file.as_ref().unwrap();
    let output_file = args.output_file.as_ref().unwrap();
    
    // Use streaming encryption
    let bytes_processed = match args.algorithm {
        Algorithm::Aes => {
            aes::encrypt_file_streaming(input_file, output_file, &key, args.mode, args.padding)?
        }
        Algorithm::Des => {
            des::encrypt_file_streaming(input_file, output_file, &key, args.mode, args.padding)?
        }
        Algorithm::Rsa => {
            return Err(CryptoError::InvalidArgument("Streaming not supported for RSA encryption".to_string()));
        }
    };
    
    println!("Encrypted {bytes_processed} bytes using streaming I/O");
    Ok(())
}

fn handle_decrypt_streaming(args: CryptoArgs) -> Result<()> {
    // Load key (only for symmetric algorithms)
    let key = if args.algorithm == Algorithm::Rsa {
        return Err(CryptoError::InvalidArgument("Streaming not supported for RSA decryption".to_string()));
    } else if let Some(key_str) = &args.key {
        load_key_from_string(key_str, args.algorithm)?
    } else if let Some(key_file) = &args.key_file {
        load_key_from_file(key_file, args.algorithm)?
    } else {
        return Err(CryptoError::InvalidArgument("Must provide either --key or --key-file".to_string()));
    };
    
    let input_file = args.input_file.as_ref().unwrap();
    let output_file = args.output_file.as_ref().unwrap();
    
    // Use streaming decryption
    let bytes_processed = match args.algorithm {
        Algorithm::Aes => {
            aes::decrypt_file_streaming(input_file, output_file, &key, args.mode, args.padding)?
        }
        Algorithm::Des => {
            des::decrypt_file_streaming(input_file, output_file, &key, args.mode, args.padding)?
        }
        Algorithm::Rsa => {
            return Err(CryptoError::InvalidArgument("Streaming not supported for RSA decryption".to_string()));
        }
    };
    
    println!("Decrypted {bytes_processed} bytes using streaming I/O");
    Ok(())
}

fn handle_decrypt(args: CryptoArgs) -> Result<()> {
    validate_input_source(&args.input_data, &args.input_file)?;
    
    // Check if we should use streaming for file operations
    if args.stream && args.input_file.is_some() && args.output_file.is_some() {
        return handle_decrypt_streaming(args);
    }
    
    // Load input data
    let data = if args.algorithm == Algorithm::Rsa {
        // For RSA, handle base64 decoding of input data
        if let Some(data) = &args.input_data {
            // Assume input data is base64 encoded for RSA
            base64_decode(data)?
        } else {
            // For file input, assume it's base64 encoded (since we save RSA as base64)
            let input_source = InputSource::File(args.input_file.as_ref().unwrap());
            let file_data = read_input(input_source)?;
            let file_str = String::from_utf8(file_data)
                .map_err(|_| CryptoError::InvalidArgument("Invalid file encoding for RSA decryption".to_string()))?;
            base64_decode(&file_str)?
        }
    } else {
        // For symmetric algorithms, use normal input handling
        let input_source = if let Some(data) = &args.input_data {
            InputSource::Inline(data)
        } else {
            InputSource::File(args.input_file.as_ref().unwrap())
        };
        read_input(input_source)?
    };
    
    // Decrypt data based on algorithm
    let plaintext = match args.algorithm {
        Algorithm::Aes | Algorithm::Des => {
            // Load symmetric key
            let key = if let Some(key_str) = &args.key {
                load_key_from_string(key_str, args.algorithm)?
            } else if let Some(key_file) = &args.key_file {
                load_key_from_file(key_file, args.algorithm)?
            } else {
                return Err(crate::error::CryptoError::InvalidArgument("Must provide either --key or --key-file".to_string()));
            };
            
            // Extract IV/nonce and ciphertext
            let (iv_or_nonce, ciphertext) = match args.algorithm {
                Algorithm::Aes => {
                    let iv_len = match args.mode {
                        Mode::Cbc => 16,
                        Mode::Gcm => 12,
                        _ => return Err(crate::error::CryptoError::InvalidArgument("Unsupported mode for decryption".to_string())),
                    };
                    if data.len() < iv_len {
                        return Err(crate::error::CryptoError::InvalidArgument("Invalid encrypted data format".to_string()));
                    }
                    let (iv, cipher) = data.split_at(iv_len);
                    (iv.to_vec(), cipher.to_vec())
                }
                Algorithm::Des => {
                    let iv_len = 8; // DES block size
                    if data.len() < iv_len {
                        return Err(crate::error::CryptoError::InvalidArgument("Invalid encrypted data format".to_string()));
                    }
                    let (iv, cipher) = data.split_at(iv_len);
                    (iv.to_vec(), cipher.to_vec())
                }
                _ => unreachable!(),
            };
            
            // Decrypt symmetric data
            match args.algorithm {
                Algorithm::Aes => aes::decrypt(&ciphertext, &key, args.mode, args.padding, &iv_or_nonce)?,
                Algorithm::Des => des::decrypt(&ciphertext, &key, args.mode, args.padding, &iv_or_nonce)?,
                _ => unreachable!(),
            }
        }
        Algorithm::Rsa => {
            // Load RSA private key
            let private_key = if let Some(key_path) = &args.private_key {
                rsa::load_private_key_pem(key_path)?
            } else {
                return Err(crate::error::CryptoError::InvalidArgument("RSA decryption requires --private-key".to_string()));
            };
            
            // Use chunked decryption for RSA (force PKCS1 padding for RSA)
            let rsa_padding = match args.padding {
                Padding::Pkcs1 | Padding::OaepSha256 => args.padding,
                _ => Padding::Pkcs1, // Default to PKCS1 for RSA
            };
            rsa::decrypt_chunked(&data, &private_key, rsa_padding)?
        }
    };
    
    // Output result
    let output_target = if let Some(file) = &args.output_file {
        OutputTarget::File(file)
    } else {
        OutputTarget::Stdout
    };
    
    if matches!(output_target, OutputTarget::Stdout) {
        let formatted = format_output(&plaintext, args.output_encoding);
        println!("{formatted}");
    } else {
        write_output(output_target, &plaintext)?;
        println!("Decrypted data saved to file");
    }
    
    Ok(())
}

fn handle_sign(args: SignArgs) -> Result<()> {
    if args.algorithm != Algorithm::Rsa {
        return Err(CryptoError::InvalidArgument("Sign currently supports RSA only".to_string()));
    }
    
    // Load private key
    let private_key = rsa::load_private_key_pem(&args.private_key)?;
    
    // Sign the file
    let signature = rsa::sign_file(&args.input_file, &private_key)?;
    
    // Save signature
    rsa::save_signature(&signature, &args.output_sig)?;
    
    println!("File signed successfully. Signature saved to: {}", args.output_sig);
    Ok(())
}

fn handle_verify(args: VerifyArgs) -> Result<()> {
    if args.algorithm != Algorithm::Rsa {
        return Err(CryptoError::InvalidArgument("Verify currently supports RSA only".to_string()));
    }
    
    // Load public key
    let public_key = rsa::load_public_key_pem(&args.public_key)?;
    
    // Load signature
    let signature = rsa::load_signature(&args.signature)?;
    
    // Verify signature
    let is_valid = rsa::verify_file(&args.input_file, &signature, &public_key)?;
    
    if is_valid {
        println!("✓ Signature is valid");
    } else {
        println!("✗ Signature is invalid");
        std::process::exit(1);
    }
    
    Ok(())
}

fn validate_input_source(input_data: &Option<String>, input_file: &Option<String>) -> Result<()> {
    if input_data.is_some() && input_file.is_some() {
        return Err(crate::error::CryptoError::Message("Provide either --input-data or --input-file, not both".to_string()));
    }
    if input_data.is_none() && input_file.is_none() {
        return Err(crate::error::CryptoError::Message("Must provide one of --input-data or --input-file".to_string()));
    }
    Ok(())
}

fn load_key_from_string(key_str: &str, algorithm: Algorithm) -> Result<Vec<u8>> {
    // Try to detect encoding automatically
    let encoding = if key_str.chars().all(|c| c.is_ascii_hexdigit()) {
        OutputEncoding::Hex
    } else if key_str.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=') {
        OutputEncoding::Base64
    } else {
        OutputEncoding::Utf8
    };
    
    match algorithm {
        Algorithm::Aes => aes::load_key(key_str, encoding),
        Algorithm::Des => des::load_key(key_str, encoding),
        Algorithm::Rsa => Err(crate::error::CryptoError::InvalidArgument("RSA keys should be loaded from PEM files".to_string())),
    }
}

fn load_key_from_file(key_file: &str, algorithm: Algorithm) -> Result<Vec<u8>> {
    let key_data = std::fs::read(key_file)?;
    let key_str = String::from_utf8_lossy(&key_data);
    
    // Try to parse as formatted key first
    if let Some(key) = parse_formatted_key(&key_str, algorithm) {
        return Ok(key);
    }
    
    // Fall back to raw bytes
    match algorithm {
        Algorithm::Aes => {
            if key_data.len() == 32 {
                Ok(key_data)
            } else {
                Err(crate::error::CryptoError::InvalidArgument("AES-256 requires 32-byte key file".to_string()))
            }
        }
        Algorithm::Des => {
            if key_data.len() == 8 {
                Ok(key_data)
            } else {
                Err(crate::error::CryptoError::InvalidArgument("DES requires 8-byte key file".to_string()))
            }
        }
        Algorithm::Rsa => Err(crate::error::CryptoError::InvalidArgument("RSA keys should be loaded from PEM files using --private-key or --public-key".to_string())),
    }
}

fn parse_formatted_key(key_str: &str, algorithm: Algorithm) -> Option<Vec<u8>> {
    match algorithm {
        Algorithm::Aes => {
            // Look for "AES-256 key (Base64): " pattern
            if let Some(start) = key_str.find("AES-256 key (Base64): ") {
                let key_part = &key_str[start + "AES-256 key (Base64): ".len()..];
                if let Some(end) = key_part.find('\n') {
                    let key_b64 = &key_part[..end];
                    return base64_decode(key_b64).ok();
                } else {
                    return base64_decode(key_part.trim()).ok();
                }
            }
            // Look for "AES-128 key (Base64): " pattern
            if let Some(start) = key_str.find("AES-128 key (Base64): ") {
                let key_part = &key_str[start + "AES-128 key (Base64): ".len()..];
                if let Some(end) = key_part.find('\n') {
                    let key_b64 = &key_part[..end];
                    return base64_decode(key_b64).ok();
                } else {
                    return base64_decode(key_part.trim()).ok();
                }
            }
            // Look for "AES-192 key (Base64): " pattern
            if let Some(start) = key_str.find("AES-192 key (Base64): ") {
                let key_part = &key_str[start + "AES-192 key (Base64): ".len()..];
                if let Some(end) = key_part.find('\n') {
                    let key_b64 = &key_part[..end];
                    return base64_decode(key_b64).ok();
                } else {
                    return base64_decode(key_part.trim()).ok();
                }
            }
        }
        Algorithm::Des => {
            // Look for "DES key (Base64): " pattern
            if let Some(start) = key_str.find("DES key (Base64): ") {
                let key_part = &key_str[start + "DES key (Base64): ".len()..];
                if let Some(end) = key_part.find('\n') {
                    let key_b64 = &key_part[..end];
                    return base64_decode(key_b64).ok();
                } else {
                    return base64_decode(key_part.trim()).ok();
                }
            }
            // Look for "3DES key (Base64): " pattern
            if let Some(start) = key_str.find("3DES key (Base64): ") {
                let key_part = &key_str[start + "3DES key (Base64): ".len()..];
                if let Some(end) = key_part.find('\n') {
                    let key_b64 = &key_part[..end];
                    return base64_decode(key_b64).ok();
                } else {
                    return base64_decode(key_part.trim()).ok();
                }
            }
        }
        Algorithm::Rsa => {
            // RSA keys are handled separately
        }
    }
    None
}

fn format_output(data: &[u8], encoding: OutputEncoding) -> String {
    match encoding {
        OutputEncoding::Base64 => base64_encode(data),
        OutputEncoding::Hex => hex_encode(data),
        OutputEncoding::Utf8 => {
            // Try to convert to UTF-8 string, fallback to hex if invalid
            String::from_utf8(data.to_vec()).unwrap_or_else(|_| hex_encode(data))
        }
    }
}
