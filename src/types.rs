use clap::ValueEnum;

#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
pub enum Algorithm {
    Aes,
    Des,
    Rsa,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
pub enum Mode {
    Cbc,
    Gcm,
    Ecb,
    Ctr,
    Ofb,
    Cfb,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
pub enum Padding {
    Pkcs5,
    NoPadding,
    // RSA paddings
    Pkcs1,
    OaepSha256,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, ValueEnum)]
pub enum OutputEncoding {
    Utf8,
    Base64,
    Hex,
}
