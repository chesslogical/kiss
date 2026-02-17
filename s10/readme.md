---

# SecureApp

SecureApp is a minimal, safety-focused file encryption tool written in Rust.

It provides safe in-place encryption and decryption using modern, authenticated cryptography with strong corruption protections.

---

## Features

* In-place encryption and decryption
* Atomic file replacement (no partial overwrite corruption)
* Automatic backup during processing
* Authenticated encryption (AEAD)
* Chunked processing (large file safe)
* Memory-hard password derivation (Argon2id)
* Password input hidden from terminal
* No silent truncation or partial reads
* Strict format validation

---

## Usage

```
secureapp E <file>
secureapp D <file>
```

Uppercase required:

* `E` → Encrypt
* `D` → Decrypt

Examples:

```
secureapp E document.pdf
secureapp D document.pdf
```

---

## How It Works

Encryption:

1. Creates a temporary file.
2. Encrypts the original file into the temp file.
3. Flushes and finalizes output.
4. Renames the original to a backup.
5. Atomically replaces the original with the encrypted file.
6. Removes the backup after success.

Decryption follows the same process in reverse.

If anything fails, the original file remains intact.

---

## Cryptography

* Cipher: XChaCha20-Poly1305 (AEAD)
* Key derivation: Argon2id
* Per-file random salt
* Per-chunk nonce derivation
* Authenticated header validation

Each chunk is authenticated to prevent tampering.

---

## Security Notes

* Wrong password will fail safely.
* Corrupted files will not partially decrypt.
* Chunk sizes are validated to prevent memory abuse.
* No unwraps or panics in crypto path.
* Password memory is zeroized after use.

---

## Build

Requires Rust 1.70+ (recommended stable).

```
cargo build --release
```

Binary will be located at:

```
target/release/secureapp
```

---

## Design Philosophy

SecureApp prioritizes:

* Data safety over convenience
* Atomic operations
* Explicit failure handling
* No silent data loss
* Minimal attack surface

---

## Limitations

* Single-file encryption only
* Password-based encryption only
* No key files or public key support (yet)

---

## Future Ideas

* Keyfile support
* Directory mode
* Secure wipe option
* Crash recovery detection
* File format versioning upgrades

---


