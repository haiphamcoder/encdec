use crate::types::{Algorithm, Mode, OutputEncoding, Padding};
use crate::crypto::{aes, des, rsa};
use crate::error::Result;
use crate::util::{read_input, write_output, InputSource, OutputTarget, base64_encode, hex_encode};
use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "encdec", about = "Cryptography CLI utility", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Generate keys
    Keygen(KeygenArgs),
    /// Encrypt data/file
    Encrypt(CryptoArgs),
    /// Decrypt data/file
    Decrypt(CryptoArgs),
    /// Sign file (RSA)
    Sign(SignArgs),
    /// Verify signature (RSA)
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

    /// Provide key material directly
    #[arg(long = "key")]
    pub key: Option<String>,
    /// Or read key from file
    #[arg(long = "key-file")]
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
    match cli.command {
        Commands::Keygen(args) => handle_keygen(args),
        Commands::Encrypt(args) => handle_encrypt(args),
        Commands::Decrypt(args) => handle_decrypt(args),
        Commands::Sign(args) => handle_sign(args),
        Commands::Verify(args) => handle_verify(args),
    }
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
                println!("RSA private key saved to: {}", private_path);
            }
            
            if let Some(ref public_path) = args.public_out {
                rsa::save_public_key_pem(&public_key, public_path)?;
                println!("RSA public key saved to: {}", public_path);
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
    
    // Load input data
    let input_source = if let Some(data) = &args.input_data {
        InputSource::Inline(data)
    } else {
        InputSource::File(args.input_file.as_ref().unwrap())
    };
    let data = read_input(input_source)?;
    
    // Load key
    let key = if let Some(key_str) = &args.key {
        load_key_from_string(key_str, args.algorithm)?
    } else if let Some(key_file) = &args.key_file {
        load_key_from_file(key_file, args.algorithm)?
    } else {
        return Err(crate::error::CryptoError::InvalidArgument("Must provide either --key or --key-file".to_string()));
    };
    
    // Encrypt data
    let (ciphertext, iv_or_nonce) = match args.algorithm {
        Algorithm::Aes => aes::encrypt(&data, &key, args.mode, args.padding)?,
        Algorithm::Des => des::encrypt(&data, &key, args.mode, args.padding)?,
        Algorithm::Rsa => return Err(crate::error::CryptoError::InvalidArgument("Use RSA-specific commands for RSA encryption".to_string())),
    };
    
    // Combine IV/nonce with ciphertext for output
    let mut output = Vec::new();
    output.extend_from_slice(&iv_or_nonce);
    output.extend_from_slice(&ciphertext);
    
    // Output result
    let output_target = if let Some(file) = &args.output_file {
        OutputTarget::File(file)
    } else {
        OutputTarget::Stdout
    };
    
    if matches!(output_target, OutputTarget::Stdout) {
        let formatted = format_output(&output, args.output_encoding);
        println!("{}", formatted);
    } else {
        write_output(output_target, &output)?;
        println!("Encrypted data saved to file");
    }
    
    Ok(())
}

fn handle_decrypt(args: CryptoArgs) -> Result<()> {
    validate_input_source(&args.input_data, &args.input_file)?;
    
    // Load input data
    let input_source = if let Some(data) = &args.input_data {
        InputSource::Inline(data)
    } else {
        InputSource::File(args.input_file.as_ref().unwrap())
    };
    let data = read_input(input_source)?;
    
    // Load key
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
        Algorithm::Rsa => return Err(crate::error::CryptoError::InvalidArgument("Use RSA-specific commands for RSA decryption".to_string())),
    };
    
    // Decrypt data
    let plaintext = match args.algorithm {
        Algorithm::Aes => aes::decrypt(&ciphertext, &key, args.mode, args.padding, &iv_or_nonce)?,
        Algorithm::Des => des::decrypt(&ciphertext, &key, args.mode, args.padding, &iv_or_nonce)?,
        Algorithm::Rsa => return Err(crate::error::CryptoError::InvalidArgument("Use RSA-specific commands for RSA decryption".to_string())),
    };
    
    // Output result
    let output_target = if let Some(file) = &args.output_file {
        OutputTarget::File(file)
    } else {
        OutputTarget::Stdout
    };
    
    if matches!(output_target, OutputTarget::Stdout) {
        let formatted = format_output(&plaintext, args.output_encoding);
        println!("{}", formatted);
    } else {
        write_output(output_target, &plaintext)?;
        println!("Decrypted data saved to file");
    }
    
    Ok(())
}

fn handle_sign(args: SignArgs) -> Result<()> {
    if args.algorithm != Algorithm::Rsa {
        return Err(crate::error::CryptoError::Message("sign currently supports RSA only".to_string()));
    }
    println!(
        "[sign] alg=RSA sig_alg={} priv_key={} input={} out_sig={}",
        args.sig_alg, args.private_key, args.input_file, args.output_sig
    );
    Ok(())
}

fn handle_verify(args: VerifyArgs) -> Result<()> {
    if args.algorithm != Algorithm::Rsa {
        return Err(crate::error::CryptoError::Message("verify currently supports RSA only".to_string()));
    }
    println!(
        "[verify] alg=RSA sig_alg={} pub_key={} input={} sig={}",
        args.sig_alg, args.public_key, args.input_file, args.signature
    );
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
