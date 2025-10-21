# Contributing to encdec

Thank you for your interest in contributing to encdec! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Release Process](#release-process)

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Rust 1.75 or later
- Cargo
- Git

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

   ```bash
   git clone https://github.com/haiphamcoder/encdec.git
   cd encdec
   ```

3. Add the upstream repository:

   ```bash
   git remote add upstream https://github.com/haiphamcoder/encdec.git
   ```

## Development Setup

### Quick Start

```bash
# Clone the repository
git clone https://github.com/haiphamcoder/encdec.git
cd encdec

# Install development dependencies
make dev-setup

# Run tests
make test

# Build the project
make build-release
```

### Manual Setup

```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install additional tools
cargo install cargo-audit
cargo install cargo-criterion
cargo install cargo-tarpaulin  # For coverage

# Verify installation
cargo --version
rustc --version
```

## Project Structure

```text
encdec/
├── src/
│   ├── main.rs          # Binary entry point
│   ├── lib.rs           # Library entry point
│   ├── cli.rs           # CLI argument parsing
│   ├── types.rs         # Common type definitions
│   ├── error.rs         # Error handling
│   ├── util.rs          # Utility functions
│   ├── streaming.rs     # Streaming I/O
│   └── crypto/          # Cryptographic implementations
│       ├── mod.rs
│       ├── aes.rs       # AES encryption
│       ├── des.rs       # DES/3DES encryption
│       └── rsa.rs       # RSA encryption/signatures
├── tests/               # Integration tests
├── benches/             # Performance benchmarks
├── .github/workflows/   # CI/CD pipelines
├── Cargo.toml          # Project configuration
├── Makefile            # Build automation
├── Dockerfile          # Container build
└── README.md           # Project documentation
```

## Coding Standards

### Rust Style

- Follow the official Rust style guide
- Use `cargo fmt` to format code
- Use `cargo clippy` to catch common issues
- Prefer explicit error handling over panics
- Use meaningful variable and function names
- Add documentation for public APIs

### Code Organization

- Keep functions small and focused
- Use modules to organize related functionality
- Prefer composition over inheritance
- Use `Result<T>` for fallible operations
- Use `Option<T>` for optional values

### Security Considerations

- Never log sensitive data (keys, passwords, plaintext)
- Use secure random number generation
- Validate all inputs
- Use constant-time operations where appropriate
- Follow cryptographic best practices

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run specific test suites
make test-unit
make test-integration
make test-performance

# Run tests with coverage
cargo tarpaulin --out Html
```

### Test Categories

1. **Unit Tests**: Test individual functions and modules
2. **Integration Tests**: Test CLI commands and workflows
3. **Performance Tests**: Benchmark cryptographic operations
4. **Security Tests**: Verify cryptographic correctness

### Writing Tests

- Write tests for all public APIs
- Test both success and failure cases
- Use descriptive test names
- Clean up temporary files
- Mock external dependencies when possible

Example test structure:

```rust
#[test]
fn test_aes_encryption_roundtrip() {
    let key = aes::generate_key(256).unwrap();
    let data = b"test data";
    
    let ciphertext = aes::encrypt_cbc(data, &key, &iv).unwrap();
    let plaintext = aes::decrypt_cbc(&ciphertext, &key, &iv).unwrap();
    
    assert_eq!(plaintext, data);
}
```

## Submitting Changes

### Workflow

1. **Create a feature branch**:

   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Write code following the coding standards
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**:

   ```bash
   make test
   make check
   ```

4. **Commit your changes**:

   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

5. **Push and create a PR**:

   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Message Format

Use conventional commits format:

- `feat:` for new features
- `fix:` for bug fixes
- `docs:` for documentation changes
- `test:` for test additions/changes
- `refactor:` for code refactoring
- `perf:` for performance improvements
- `chore:` for maintenance tasks

Examples:

```text
feat: add AES-GCM encryption support
fix: resolve key loading issue with formatted keys
docs: update README with streaming examples
test: add performance benchmarks for RSA operations
```

### Pull Request Guidelines

- Provide a clear description of changes
- Reference any related issues
- Ensure all tests pass
- Request review from maintainers
- Respond to feedback promptly

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Steps

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create release tag
4. Build and test all platforms
5. Create GitHub release
6. Publish to crates.io (if applicable)

### Building Releases

```bash
# Build all platforms
make release-all

# Build specific platform
make release-linux
make release-windows
make release-macos
```

## Performance Guidelines

### Benchmarking

- Use `cargo bench` for performance testing
- Benchmark critical paths (encryption/decryption)
- Test with various data sizes
- Monitor memory usage
- Document performance characteristics

### Optimization

- Profile before optimizing
- Use `cargo flamegraph` for profiling
- Consider algorithm complexity
- Optimize for common use cases
- Balance speed vs. security

## Security Guidelines

### Cryptographic Security

- Use well-established algorithms
- Follow cryptographic best practices
- Implement proper key management
- Use secure random number generation
- Validate all inputs

### Code Security

- Never commit secrets or keys
- Use secure coding practices
- Regular security audits
- Keep dependencies updated
- Follow principle of least privilege

## Getting Help

- Check existing issues and discussions
- Join our community chat (if available)
- Create an issue for bugs or feature requests
- Ask questions in discussions

## License

By contributing to encdec, you agree that your contributions will be licensed under the same license as the project (MIT License).

---

Thank you for contributing to encdec! 🚀
