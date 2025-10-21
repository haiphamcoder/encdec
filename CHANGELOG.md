# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Comprehensive test suite with unit, integration, and performance tests
- GitHub Actions CI/CD pipeline for automated testing and building
- Cross-compilation support for Linux, Windows, and macOS
- Docker containerization support
- Makefile for easy build automation
- Developer documentation and contributing guidelines
- Performance benchmarking framework
- Security audit integration

### Changed

- Optimized release builds with LTO and size optimization
- Enhanced error messages and user experience
- Improved CLI help system with detailed descriptions

### Fixed

- Various test failures and compilation issues
- Memory usage optimization for large files
- Key file parsing improvements

## [0.1.0] - 2025-10-21

### Added

- Initial release of encdec
- **Key Generation**: Support for AES (128/192/256), DES/3DES, and RSA (2048/3072/4096) key generation
- **Symmetric Encryption**: AES-CBC, AES-GCM, DES-CBC encryption/decryption
- **Asymmetric Encryption**: RSA with PKCS1 and OAEP-SHA256 padding
- **Digital Signatures**: RSA digital signature creation and verification
- **Streaming I/O**: Memory-efficient processing of large files with adaptive buffering
- **Multiple Encodings**: Support for Base64, Hex, and UTF-8 input/output formats
- **CLI Interface**: Comprehensive command-line interface with subcommands
- **Security Features**: Built-in security warnings and best practices guidance
- **Performance Optimization**: Adaptive buffer sizes and optimized algorithms
- **Cross-Platform**: Native binaries for Linux, Windows, and macOS

### Features by Phase

#### Phase 1: Setup & Core Structure ✅

- Project initialization with Rust and Cargo
- CLI framework using Clap
- Cryptographic crate integration (aes, aes-gcm, rsa, etc.)
- Common type definitions and error handling
- Utility functions for encoding/decoding

#### Phase 2: Core Crypto Logic ✅

- AES key generation (128/192/256 bits)
- DES/3DES key generation (64/192 bits)
- RSA key pair generation (2048/3072/4096 bits)
- AES encryption/decryption (CBC, GCM modes)
- DES encryption/decryption (CBC mode)
- Key management and format detection
- Base64 and Hex encoding/decoding

#### Phase 3: Asymmetric Crypto & Advanced Features ✅

- RSA encryption/decryption (PKCS1, OAEP-SHA256)
- RSA key PEM serialization/deserialization
- Chunked I/O for large file processing
- Base64 I/O handling for RSA operations
- Key exchange and small data encryption

#### Phase 4: Digital Signatures & Advanced Features ✅

- RSA digital signature creation and verification
- SHA-256 hashing for signature generation
- Signature file I/O operations
- File integrity and authenticity verification
- Non-repudiation support

#### Phase 5: Streaming I/O & User Experience ✅

- Memory-efficient file processing
- Adaptive buffering (64KB-256KB based on file size)
- Enhanced CLI help system with detailed descriptions
- Comprehensive security warnings
- Performance optimizations for large files
- Improved error messages and user guidance

#### Phase 6: Testing & Distribution ✅

- Comprehensive test suite (unit, integration, performance)
- Cross-compilation support for multiple platforms
- CI/CD pipeline with GitHub Actions
- Docker containerization
- Build automation with Makefile
- Developer documentation and guidelines

### Security Considerations

- **DES/3DES**: Included for legacy compatibility only (deprecated)
- **ECB Mode**: Not implemented due to security concerns
- **Key Management**: Secure random generation and proper storage
- **Memory Safety**: Zeroization of sensitive data
- **Input Validation**: Comprehensive validation of all inputs
- **Error Handling**: Secure error reporting without information leakage

### Performance Characteristics

- **AES-256-CBC**: ~100-200 MB/s on modern hardware
- **AES-256-GCM**: ~80-150 MB/s (includes authentication)
- **RSA-2048**: ~1-5 MB/s (chunked processing)
- **Memory Usage**: Constant ~64KB-256KB for streaming operations
- **File Support**: Unlimited file sizes with streaming I/O

### Dependencies

- **Core**: Rust standard library
- **CLI**: clap 4.5
- **Crypto**: aes 0.8, aes-gcm 0.10, rsa 0.9, des 0.8
- **Encoding**: base64 0.22, hex 0.4
- **Key Management**: pkcs8 0.10, pbkdf2 0.12
- **Error Handling**: thiserror 1.0, anyhow 1.0
- **Security**: zeroize 1.7

### Supported Platforms

- **Linux**: x86_64-unknown-linux-gnu
- **Windows**: x86_64-pc-windows-msvc
- **macOS**: x86_64-apple-darwin, aarch64-apple-darwin

### Installation

```bash
# From source
git clone https://github.com/haiphamcoder/encdec.git
cd encdec
cargo build --release

# Using cargo install
cargo install encdec

# Using pre-built binaries
# Download from GitHub releases
```

### Usage Examples

```bash
# Generate keys
encdec keygen --alg aes --size 256
encdec keygen --alg rsa --size 2048 --private-out key.pem --public-out pub.pem

# Encrypt/Decrypt
encdec encrypt --alg aes --mode cbc --key-file key.key --input-file data.txt --output-file encrypted.bin
encdec decrypt --alg aes --mode cbc --key-file key.key --input-file encrypted.bin --output-file decrypted.txt

# Digital signatures
encdec sign --alg rsa --private-key key.pem --input-file document.pdf --output-sig signature.sig
encdec verify --alg rsa --public-key pub.pem --input-file document.pdf --signature signature.sig

# Streaming for large files
encdec encrypt --alg aes --mode gcm --key-file key.key --input-file large_file.iso --output-file encrypted.iso --stream
```

---

## Version History

- **0.1.0**: Initial release with full feature set
- **Unreleased**: Testing, distribution, and developer experience improvements

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on contributing to this project.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
