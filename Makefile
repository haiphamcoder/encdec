# encdec Makefile
# Provides easy commands for building, testing, and cross-compilation

.PHONY: help build test clean install release-all

# Default target
help:
	@echo "encdec - Cross-Platform Cryptography CLI Utility"
	@echo ""
	@echo "Available targets:"
	@echo "  build          - Build the project in debug mode"
	@echo "  build-release  - Build the project in release mode"
	@echo "  test           - Run all tests"
	@echo "  test-unit      - Run unit tests only"
	@echo "  test-integration - Run integration tests only"
	@echo "  test-performance - Run performance tests"
	@echo "  clean          - Clean build artifacts"
	@echo "  install        - Install the binary to ~/.cargo/bin"
	@echo "  uninstall      - Remove the binary from ~/.cargo/bin"
	@echo "  release-all    - Build release binaries for all platforms"
	@echo "  release-linux  - Build release binary for Linux"
	@echo "  release-windows - Build release binary for Windows"
	@echo "  release-macos  - Build release binary for macOS"
	@echo "  check          - Run clippy and fmt checks"
	@echo "  audit          - Run security audit"
	@echo "  benchmark      - Run performance benchmarks"

# Build targets
build:
	cargo build

build-release:
	cargo build --release

# Test targets
test:
	cargo test

test-unit:
	cargo test --lib

test-integration:
	cargo test --test '*'

test-performance:
	cargo test --test performance_tests

# Quality checks
check:
	cargo clippy --all-targets --all-features -- -D warnings
	cargo fmt --all -- --check

audit:
	cargo audit

benchmark:
	cargo bench

# Clean
clean:
	cargo clean

# Install/Uninstall
install: build-release
	cargo install --path .

uninstall:
	cargo uninstall encdec

# Cross-compilation targets
release-all: release-linux release-windows release-macos

release-linux:
	@echo "Building for Linux (x86_64)..."
	cargo build --release --target x86_64-unknown-linux-gnu
	@mkdir -p dist
	@cp target/x86_64-unknown-linux-gnu/release/encdec dist/encdec-linux-x86_64
	@echo "Linux binary created: dist/encdec-linux-x86_64"

release-windows:
	@echo "Building for Windows (x86_64)..."
	cargo build --release --target x86_64-pc-windows-msvc
	@mkdir -p dist
	@cp target/x86_64-pc-windows-msvc/release/encdec.exe dist/encdec-windows-x86_64.exe
	@echo "Windows binary created: dist/encdec-windows-x86_64.exe"

release-macos:
	@echo "Building for macOS (x86_64 and aarch64)..."
	cargo build --release --target x86_64-apple-darwin
	cargo build --release --target aarch64-apple-darwin
	@mkdir -p dist
	@cp target/x86_64-apple-darwin/release/encdec dist/encdec-macos-x86_64
	@cp target/aarch64-apple-darwin/release/encdec dist/encdec-macos-aarch64
	@echo "macOS binaries created: dist/encdec-macos-x86_64, dist/encdec-macos-aarch64"

# Development helpers
dev-setup:
	@echo "Setting up development environment..."
	rustup component add rustfmt clippy
	cargo install cargo-audit
	cargo install cargo-criterion
	@echo "Development environment ready!"

# Docker builds (if needed)
docker-build:
	docker build -t encdec:latest .

docker-test:
	docker run --rm encdec:latest cargo test

# Documentation
docs:
	cargo doc --open

# Size analysis
size-analysis: build-release
	@echo "Binary size analysis:"
	@ls -lh target/release/encdec
	@echo ""
	@echo "Dependencies size analysis:"
	@cargo tree --duplicates
