use std::fs::File;
use std::io::{Read, Write};

use base64::{engine::general_purpose, Engine as _};

use crate::error::{CryptoError, Result};

pub fn read_file_to_bytes(path: &str) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

pub fn write_bytes_to_file(path: &str, data: &[u8]) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    Ok(())
}

pub fn base64_encode(data: &[u8]) -> String {
    general_purpose::STANDARD.encode(data)
}

pub fn base64_decode(input: &str) -> Result<Vec<u8>> {
    Ok(general_purpose::STANDARD.decode(input)?)
}

pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

pub fn hex_decode(input: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(input)?)
}

pub enum InputSource<'a> {
    Inline(&'a str),
    File(&'a str),
}

pub fn read_input(source: InputSource) -> Result<Vec<u8>> {
    match source {
        InputSource::Inline(s) => Ok(s.as_bytes().to_vec()),
        InputSource::File(p) => read_file_to_bytes(p),
    }
}

pub enum OutputTarget<'a> {
    Stdout,
    File(&'a str),
}

pub fn write_output(target: OutputTarget, data: &[u8]) -> Result<()> {
    match target {
        OutputTarget::Stdout => {
            std::io::stdout().write_all(data)?;
            Ok(())
        }
        OutputTarget::File(p) => write_bytes_to_file(p, data),
    }
}

pub fn invalid_arg<T>(message: impl Into<String>) -> Result<T> {
    Err(CryptoError::InvalidArgument(message.into()))
}
