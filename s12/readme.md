
---

# Serpent2

Linux-only file encryption tool using:

* **Serpent (256-bit)** block cipher
* **Argon2id** for password key derivation
* **HKDF-SHA256** for key separation
* **HMAC-SHA256** for authentication
* Atomic file overwrite (Linux-optimized)

This tool is designed to securely encrypt and decrypt files in-place using modern cryptographic best practices.

---

## ⚠️ Platform

**Linux only.**

This application intentionally uses Linux-specific atomic file replacement (`rename`) and permission handling.
It is not intended to compile or run on Windows or macOS.

---

## 🔐 Cryptographic Design

### Key Derivation

* Password → Argon2id
* 256-bit derived key
* Random 128-bit salt per file

### Key Separation

Derived key is expanded via HKDF into:

* Encryption key
* HMAC key

### Encryption

* Cipher: Serpent-256
* Mode: CBC
* Random IV per file

### Authentication

* HMAC-SHA256 over:

  * Salt
  * IV
  * Ciphertext

Decryption fails if authentication fails.

---

## 📦 File Format

Encrypted file structure:

```
[ magic 4 bytes ]
[ salt 16 bytes ]
[ iv 16 bytes ]
[ ciphertext ... ]
[ hmac 32 bytes ]
```

Magic header prevents accidental double-encryption.

---

## 🚀 Build

Install Rust (stable):

```bash
curl https://sh.rustup.rs -sSf | sh
```

Clone and build:

```bash
cargo build --release
```

Binary will be in:

```
target/release/serpent2
```

---

## 🔑 Usage

Encrypt:

```bash
./serpent2 encrypt file.txt mypassword
```

Decrypt:

```bash
./serpent2 decrypt file.txt mypassword
```

Or with Cargo:

```bash
cargo run -- encrypt file.txt mypassword
```

---

## 🛡 Security Properties

✔ Argon2id password hardening
✔ Random salt per file
✔ Separate encryption & authentication keys
✔ Encrypt-then-MAC construction
✔ Atomic file overwrite (no partial corruption)
✔ Constant-time HMAC verification

---

## ⚠️ Important Notes

* Password is currently passed via CLI argument (visible in shell history).
* This tool encrypts files **in place**.
* No key recovery is possible.
* Losing the password = permanent data loss.

---

## 🔒 Recommended Improvements (Future)

* Hidden password input (no CLI exposure)
* Streaming encryption for large files
* Memory zeroization
* `mlock` to prevent swap leakage
* Authenticated encryption mode (AEAD)
* Secure file wipe before overwrite

---

## 🧠 Why Serpent?

Serpent was a finalist in the AES competition and is widely regarded as highly conservative and secure. It trades some speed for a large security margin.

---

## 📄 License

MIT or Apache-2.0 (choose your preferred license).

---

