use crate::types::{Algorithm, Mode, OutputEncoding, Padding};
use anyhow::{Result, bail};
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
        Algorithm::Aes | Algorithm::Des => {
            println!(
                "[keygen] alg={:?} size={} output_encoding={:?}",
                args.algorithm, args.size, args.output_encoding
            );
        }
        Algorithm::Rsa => {
            println!(
                "[keygen] alg=RSA size={} private_out={:?} public_out={:?}",
                args.size, args.private_out, args.public_out
            );
        }
    }
    Ok(())
}

fn handle_encrypt(args: CryptoArgs) -> Result<()> {
    validate_input_source(&args.input_data, &args.input_file)?;
    println!(
        "[encrypt] alg={:?} mode={:?} padding={:?} out_enc={:?} in_data?={} in_file?={} out_file={:?}",
        args.algorithm,
        args.mode,
        args.padding,
        args.output_encoding,
        args.input_data.is_some(),
        args.input_file.is_some(),
        args.output_file
    );
    Ok(())
}

fn handle_decrypt(args: CryptoArgs) -> Result<()> {
    validate_input_source(&args.input_data, &args.input_file)?;
    println!(
        "[decrypt] alg={:?} mode={:?} padding={:?} out_enc={:?} in_data?={} in_file?={} out_file={:?}",
        args.algorithm,
        args.mode,
        args.padding,
        args.output_encoding,
        args.input_data.is_some(),
        args.input_file.is_some(),
        args.output_file
    );
    Ok(())
}

fn handle_sign(args: SignArgs) -> Result<()> {
    if args.algorithm != Algorithm::Rsa {
        bail!("sign currently supports RSA only");
    }
    println!(
        "[sign] alg=RSA sig_alg={} priv_key={} input={} out_sig={}",
        args.sig_alg, args.private_key, args.input_file, args.output_sig
    );
    Ok(())
}

fn handle_verify(args: VerifyArgs) -> Result<()> {
    if args.algorithm != Algorithm::Rsa {
        bail!("verify currently supports RSA only");
    }
    println!(
        "[verify] alg=RSA sig_alg={} pub_key={} input={} sig={}",
        args.sig_alg, args.public_key, args.input_file, args.signature
    );
    Ok(())
}

fn validate_input_source(input_data: &Option<String>, input_file: &Option<String>) -> Result<()> {
    if input_data.is_some() && input_file.is_some() {
        bail!("Provide either --input-data or --input-file, not both");
    }
    if input_data.is_none() && input_file.is_none() {
        bail!("Must provide one of --input-data or --input-file");
    }
    Ok(())
}
