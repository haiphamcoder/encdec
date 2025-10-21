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

## 📦 Usage

The tool uses a standard sub-command structure for logical separation of tasks.

### 1. Key Generation

Generates a new SecretKey (AES/DES) or a KeyPair (RSA).

#### AES Key Generation

```bash
# Generate a 256-bit AES key (default, outputs to Base64)
encdec keygen --alg aes --size 256

# Generate a 128-bit AES key in hex format
encdec keygen --alg aes --size 128 --output-encoding hex

# Generate a 192-bit AES key in UTF-8 format
encdec keygen --alg aes --size 192 --output-encoding utf8
```

#### DES/3DES Key Generation

```bash
# Generate a 64-bit DES key
encdec keygen --alg des --size 64

# Generate a 192-bit 3DES key
encdec keygen --alg des --size 192 --output-encoding hex
```

#### RSA Key Pair Generation

```bash
# Generate 2048-bit RSA key pair and save to files
encdec keygen --alg rsa --size 2048 --private-out private.pem --public-out public.pem

# Generate 4096-bit RSA key pair (keys will be generated but not saved)
encdec keygen --alg rsa --size 4096

# Generate 3072-bit RSA key pair (only private key saved)
encdec keygen --alg rsa --size 3072 --private-out private.pem
```

**Key Generation Options:**

* `-a, --alg`: Algorithm (`aes`, `des`, `rsa`) - default: `aes`
* `-s, --size`: Key size in bits (AES: 128/192/256; DES: 64/192; RSA: 2048/3072/4096) - default: `256`
* `--output-encoding`: Output format (`utf8`, `base64`, `hex`) - default: `base64`
* `--private-out`: Save RSA private key to file (PEM format)
* `--public-out`: Save RSA public key to file (PEM format)

### 2. Symmetric Encryption/Decryption ✅

Encrypts or decrypts data using a single secret key.

#### AES Encryption/Decryption

```bash
# Generate an AES-256 key
encdec keygen --alg aes --size 256 --output-encoding hex

# Encrypt string with AES-CBC (key auto-detected as hex)
encdec encrypt --alg aes --mode cbc --key "f1af7b89c64c3dfe7a62283bc3924262067163c89afcb1f1439c39c5701bfb56" \
    --input-data "Hello World!" --output-encoding base64

# Encrypt file with AES-GCM
encdec encrypt --alg aes --mode gcm --key "f1af7b89c64c3dfe7a62283bc3924262067163c89afcb1f1439c39c5701bfb56" \
    --input-file document.pdf --output-file document.enc

# Decrypt file with AES-CBC
encdec decrypt --alg aes --mode cbc --key "f1af7b89c64c3dfe7a62283bc3924262067163c89afcb1f1439c39c5701bfb56" \
    --input-file document.enc --output-file document.pdf
```

#### DES/3DES Encryption/Decryption

```bash
# Generate a DES key
encdec keygen --alg des --size 64 --output-encoding hex

# Encrypt with DES-CBC
encdec encrypt --alg des --mode cbc --key "2c9e556faeb89e57" \
    --input-file sensitive.txt --output-file sensitive.enc

# Decrypt with DES-CBC
encdec decrypt --alg des --mode cbc --key "2c9e556faeb89e57" \
    --input-file sensitive.enc --output-file sensitive.txt
```

#### Key Management

```bash
# Use key from file (raw bytes)
echo -n "f1af7b89c64c3dfe7a62283bc3924262067163c89afcb1f1439c39c5701bfb56" | xxd -r -p > aes_key.bin
encdec encrypt --alg aes --mode cbc --key-file aes_key.bin \
    --input-data "Secret message" --output-encoding hex

# Use base64 encoded key
encdec encrypt --alg aes --mode cbc --key "8a9+ZkxN/npiKIO8OSQmIGdxY8ia/LHxQ5w5xXAb+1Y=" \
    --input-data "Secret message" --output-encoding base64
```

**Symmetric Encryption Options:**

* `-a, --alg`: Algorithm (`aes`, `des`) - default: `aes`
* `-m, --mode`: Cipher mode (`cbc`, `gcm`) - default: `cbc`
* `-p, --padding`: Padding scheme (`pkcs5`) - default: `pkcs5`
* `-k, --key`: Secret key (auto-detects hex/base64/utf8)
* `--key-file`: Read key from file (raw bytes)
* `--input-data`: Input as string
* `--input-file`: Input from file
* `--output-file`: Save to file (if omitted, prints to stdout)
* `--output-encoding`: Output format (`utf8`, `base64`, `hex`) - default: `base64`

**Note:** Encrypted output includes IV/nonce prepended to ciphertext for proper decryption.

### 3. Asymmetric Encryption (RSA) ✅

Encrypts with a public key and decrypts with a private key.

#### RSA Key Generation

```bash
# Generate RSA-2048 key pair
encdec keygen --alg rsa --size 2048 --private-out private.pem --public-out public.pem

# Generate RSA-4096 key pair
encdec keygen --alg rsa --size 4096 --private-out private_4096.pem --public-out public_4096.pem
```

#### RSA Encryption/Decryption

```bash
# Encrypt string with PKCS1 padding
encdec encrypt --alg rsa --padding pkcs1 --public-key public.pem \
    --input-data "Secret message" --output-encoding base64

# Encrypt file with OAEP-SHA256 padding
encdec encrypt --alg rsa --padding oaep-sha256 --public-key public.pem \
    --input-file document.pdf --output-file document.enc

# Decrypt with PKCS1 padding
encdec decrypt --alg rsa --padding pkcs1 --private-key private.pem \
    --input-file document.enc --output-file document.pdf

# Decrypt base64 string with OAEP-SHA256
echo "AAABAKjKVaVaJ9ZwPVxzxoje2KSvp+Sd8L7bFlaYBqL7cvI9d24q5bUvgnjMTaTgq/apbsI08nezGa3JRCKrXs+BX/neyKa4cMwhiNSXz+/AHBjmg6ZdkjhxzWDDfPEvHH/8jTmVooSb5SM/PPoAWUNf14/skcntGeu+aGv1XutsL1xG8krHn/rmhYT8GKFnunRPOy0e/iVyzOLSTfLwIoUu+TB+0AzrsvVsTe1SmuSRdjrqm5nJkID3cKCPLsNUZx2dkW/L98rGRT/BP3f/8B1K4Nk4X4SEaXaOAcW8Z3k5D+GrGLUW80FlJ3Nei9aGIHoLaysmvO9ht3/WcXfnPJBCMys=" | \
encdec decrypt --alg rsa --padding oaep-sha256 --private-key private.pem --input-data "$(cat)"
```

#### Large File Encryption

```bash
# Encrypt large file (automatically chunked)
encdec encrypt --alg rsa --padding pkcs1 --public-key public.pem \
    --input-file large_database.sql --output-file large_database.enc

# Decrypt large file (automatically reassembled)
encdec decrypt --alg rsa --padding pkcs1 --private-key private.pem \
    --input-file large_database.enc --output-file large_database.sql
```

**RSA Encryption Options:**

* `-a, --alg`: Algorithm (`rsa`) - required for RSA operations
* `-p, --padding`: Padding scheme (`pkcs1`, `oaep-sha256`) - default: `pkcs1`
* `--public-key`: RSA public key file (PEM format) - required for encryption
* `--private-key`: RSA private key file (PEM format) - required for decryption
* `--input-data`: Input as string (base64 decoded for decryption)
* `--input-file`: Input from file (base64 decoded for decryption)
* `--output-file`: Save to file (base64 encoded for encryption)
* `--output-encoding`: Output format for decryption (`utf8`, `base64`, `hex`) - default: `utf8`

**RSA Key Sizes:**

* **2048 bits**: Minimum recommended size, good for most applications
* **3072 bits**: High security, recommended for sensitive data
* **4096 bits**: Maximum security, suitable for long-term storage

**Padding Schemes:**

* **PKCS1**: Legacy padding, faster but less secure
* **OAEP-SHA256**: Modern padding, more secure, recommended for new applications

**Note:** RSA encrypted output is always base64 encoded for consistency. Large files are automatically chunked during encryption and reassembled during decryption.

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

## 🏗️ Project Directory Structure

The project follows standard Cargo conventions, ensuring clear separation between the command-line interface logic (`cli.rs`) and the core cryptographic implementation (`crypto/`).

```text
encdec/
├── Cargo.toml
├── README.md             
├── src/
│   ├── main.rs           # Main entry point, calls cli::run()
│   ├── cli.rs            # Defines Clap CLI structure, handles argument parsing and command dispatch
│   ├── types.rs          # Shared Enums: Algorithm, Mode, Padding, Encoding, etc.
│   ├── error.rs          # Custom error handling structure (e.g., CryptoError)
│   ├── util.rs           # Utility functions: Hex/Base64 encoding/decoding, general file I/O helpers.
│   └── crypto/           # Core Cryptographic Implementations
│       ├── mod.rs        # Declares public modules (aes, des, rsa)
│       ├── aes.rs        # AES logic (KeyGen, CBC, GCM, Enc/Dec)
│       ├── des.rs        # DES/Triple DES logic (Legacy implementation)
│       └── rsa.rs        # RSA logic (KeyGen, Enc/Dec, Sign/Verify, Chunking)
└── tests/
    ├── integration_tests.rs # E2E tests for CLI commands
    └── crypto_vectors.rs  # Unit tests using known cryptographic test vectors
```

## 🗺️ Implementation Roadmap

The development will follow a phased approach, prioritizing security and core functionality.

### Phase 1: Setup & Core Structure ✅ COMPLETED

| Task | Detail | Status |
| :--- | :--- | :--- |
| **Project Setup & CLI** | Initialize Rust project, set up **Clap** for CLI structure. | ✅ Done |
| **Crypto Crate Selection**| Integrate `aes`, `gcm`, `block-modes`, `rsa`, `pbkdf2`. | ✅ Done |
| **Type Definition** | Define common `enum`s for `Algorithm`, `Mode`, `Padding`, `Encoding`. | ✅ Done |
| **Error Handling** | Implement a global error type for consistent reporting. | ✅ Done |

### Phase 2: Core Crypto Logic ✅ COMPLETED

| Task | Detail | Status |
| :--- | :--- | :--- |
| **Key Generation** | Implement AES/DES/RSA key generation with CLI integration. | ✅ Done |
| **AES Encryption** | Implement AES (128/192/256) with CBC and GCM modes, PKCS7 padding. | ✅ Done |
| **DES Encryption** | Implement DES/3DES with CBC mode for backward compatibility. | ✅ Done |
| **Symmetric CLI** | Implement encrypt/decrypt commands with file and string I/O. | ✅ Done |
| **Key Management** | Auto-detect key encoding (hex/base64/utf8), file-based key loading. | ✅ Done |
| **Encoding/Decoding** | Implement `encode` and `decode` helpers for Base64 and Hex to support string I/O. | ✅ Done |

### Phase 3: Asymmetric Crypto & Advanced Features ✅ COMPLETED

| Task | Detail | Status |
| :--- | :--- | :--- |
| **RSA Operations** | Implement RSA KeyGen (2048/4096), Import/Export, and encryption/decryption with **PKCS1** and **OAEP**. | ✅ Done |
| **RSA Chunking** | Implement chunked I/O for large files with automatic chunking and reassembly. | ✅ Done |
| **RSA CLI Integration** | Implement encrypt/decrypt commands with base64 I/O handling. | ✅ Done |
| **RSA Key Management** | Implement PEM key loading and saving for RSA operations. | ✅ Done |

### Phase 4: Digital Signatures & Advanced Features (In Progress)

| Task | Detail | Status |
| :--- | :--- | :--- |
| **RSA Signatures** | Implement `sign` and `verify` functionality for digital signatures (e.g., SHA256withRSA). | 🔄 In Progress |
| **File I/O Streaming**| Implement streaming I/O for very large files. | 🔄 In Progress |
| **User Experience** | Refine CLI help messages, error reporting, and security warnings. | 🔄 In Progress |

### Phase 5: Testing & Distribution (Target: 1 Week)

| Task | Detail | Deployment Goal |
| :--- | :--- | :--- |
| **Testing** | Implement comprehensive unit and integration tests across all crypto modules. | Code Quality |
| **Build & Release** | Finalize `Cargo.toml` for cross-compilation (using `cross` or GitHub Actions), and prepare binaries for Linux, Windows, and macOS. | **Cross-Platform** |
| **Documentation** | Finalize README, man pages (if applicable), and usage examples. | User Adoption |
