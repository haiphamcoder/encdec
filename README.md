# ⚡ encdec: A Cross-Platform Cryptography CLI Utility (Rust)

**`encdec`** is a command-line interface (CLI) utility written in **Rust** designed for secure, fast, and cross-platform handling of cryptographic operations, including symmetric encryption (AES, DES/3DES) and asymmetric encryption (RSA).

## ⚠️ Security Warning

* **DES/Triple DES (3DES):** Both DES and 3DES are cryptographically weak or deprecated. **They should not be used for new applications.** `encdec` includes them for legacy compatibility only.
* **ECB Mode:** The Electronic Codebook (ECB) mode of operation is **insecure** as it does not hide data patterns. **Always prefer modes like CBC, CTR, or GCM.**
* **Recommendation:** For modern applications, use **AES-256** in **GCM** mode. For key exchange and signatures, use **RSA 3072/4096** bits with **OAEP padding**.

## 🚀 Key Features

* **Cross-Platform:** Built with Rust for native binaries on Linux, Windows, and macOS.
* **Symmetric Ciphers:** AES (128, 192, 256) and Legacy DES/Triple DES (DESede).
* **Asymmetric Cipher:** RSA (2048, 3072, 4096) for key exchange and small data encryption.
* **Modes & Padding:** Supports standard modes like CBC, ECB, CTR, OFB, CFB, GCM, and padding schemes like PKCS5Padding, NoPadding, PKCS1Padding, and OAEP.
* **File Handling:** Efficient chunked I/O for encrypting/decrypting large files without running out of memory.
* **Encoding Support:** Seamlessly handle input/output data in UTF-8, Base64, and Hex formats.

## 📦 Usage (Planned CLI Structure)

The tool uses a standard sub-command structure for logical separation of tasks.

### 1. Key Generation

Generates a new SecretKey (AES/DES) or a KeyPair (RSA).

```bash
# Generate a 256-bit AES key and output to Base64
encdec keygen aes --size 256 --output-encoding base64 

# Generate a 4096-bit RSA key pair (Private key is PKCS8, Public key is X509)
encdec keygen rsa --size 4096 --private-out private.pem --public-out public.pem
````

### 2\. Symmetric Encryption/Decryption

Encrypts or decrypts data using a single secret key.

| Argument | Description | Default |
| :--- | :--- | :--- |
| `-a, --alg` | Algorithm: `aes` or `des/3des` | `aes` |
| `-m, --mode` | Cipher mode: `cbc`, `gcm`, `ecb`, etc. | `cbc` |
| `-p, --padding`| Padding scheme: `pkcs5`, `nopadding`, etc. | `pkcs5` |
| `-k, --key` | Secret key (Base64/Hex/File path) | (Required) |

```bash
# Encrypt string with AES-CBC, output as Base64
encdec encrypt --alg aes --mode cbc --key "mybase64key..." \
    --input-data "Hello World!" --output-encoding base64

# Decrypt an encrypted file
encdec decrypt --alg aes --mode cbc --key-file key.bin \
    --input-file data.enc --output-file data.txt
```

### 3\. Asymmetric Encryption (RSA)

Encrypts with a public key and decrypts with a private key.

```bash
# Encrypt data using an RSA public key with OAEP padding
encdec encrypt --alg rsa --padding oaep_sha256 --public-key public.pem \
    --input-file sensitive.dat --output-file sensitive.enc

# Decrypt data using the corresponding private key
encdec decrypt --alg rsa --padding oaep_sha256 --private-key private.pem \
    --input-file sensitive.enc --output-file sensitive.dat
```

### 4\. Digital Signature (RSA)

Signs a file using a private key and verifies the signature using a public key.

| Subcommand | Description |
| :--- | :--- |
| `sign` | Creates a digital signature for an input file. |
| `verify` | Verifies a digital signature against an input file and public key. |

```bash
# Sign a file using a private key and SHA256withRSA
encdec sign --alg rsa --sig-alg sha256withrsa \
    --private-key private.pem --input-file document.pdf --output-sig doc.sig

# Verify the signature
encdec verify --alg rsa --sig-alg sha256withrsa \
    --public-key public.pem --input-file document.pdf --signature doc.sig
```

## 🗺️ Implementation Roadmap

The development will follow a phased approach, prioritizing security and core functionality.

### Phase 1: Setup & Core Structure (Target: 1 Week)

| Task | Detail | Rust Crate / Files |
| :--- | :--- | :--- |
| **Project Setup & CLI** | Initialize Rust project, set up **Clap** for CLI structure. | `main.rs`, `cli.rs`, `Cargo.toml` |
| **Crypto Crate Selection**| Integrate `aes`, `gcm`, `block-modes`, `rsa`, `pbkdf2`. | Dependencies |
| **Type Definition** | Define common `enum`s for `Algorithm`, `Mode`, `Padding`, `Encoding`. | `src/types.rs` |
| **Error Handling** | Implement a global error type for consistent reporting. | `src/error.rs` (`thiserror`) |

### Phase 2: Core Crypto Logic (Target: 2-3 Weeks)

| Task | Detail | Priority |
| :--- | :--- | :--- |
| **AES & PBKDF2** | Implement AES (128/256) with CBC and **GCM** modes. Implement Key Derivation (PBKDF2 with HMAC-SHA256). | High |
| **RSA Operations** | Implement RSA KeyGen (2048/4096), Import/Export, and encryption/decryption with **PKCS1** and **OAEP**. | High |
| **Legacy DES/3DES** | Implement DES/3DES with CBC/ECB for backward compatibility only. Include prominent security warnings. | Medium |
| **Encoding/Decoding** | Implement `encode` and `decode` helpers for Base64 and Hex to support string I/O. | High |

### Phase 3: CLI Integration & Advanced Features (Target: 1-2 Weeks)

| Task | Detail | Platform Goal |
| :--- | :--- | :--- |
| **File I/O Streaming**| Implement chunked I/O using `Cipher::update` to handle large files efficiently (critical for AES/DES). | Cross-Platform |
| **RSA Signature** | Implement `sign` and `verify` functionality for digital signatures (e.g., SHA256withRSA). | Cross-Platform |
| **Secure Input** | Ensure keys are handled securely (e.g., reading from files/env vars). | Cross-Platform |
| **User Experience** | Refine CLI help messages, error reporting, and security warnings (e.g., on ECB usage). | Cross-Platform |

### Phase 4: Testing & Distribution (Target: 1 Week)

| Task | Detail | Deployment Goal |
| :--- | :--- | :--- |
| **Testing** | Implement comprehensive unit and integration tests across all crypto modules. | Code Quality |
| **Build & Release** | Finalize `Cargo.toml` for cross-compilation (using `cross` or GitHub Actions), and prepare binaries for Linux, Windows, and macOS. | **Cross-Platform** |
| **Documentation** | Finalize README, man pages (if applicable), and usage examples. | User Adoption |
