//! ============================================================
//!  SERPENT2 — LINUX-ONLY BUILD
//! ============================================================
//!
//!  This program is intentionally optimized for Linux.
//!  It relies on:
//!    - Atomic rename() semantics
//!    - Unix 0o600 file permissions
//!    - OpenOptionsExt (mode setting)
//!
//!  DO NOT port to Windows/macOS without redesigning file safety.
//! ============================================================

#![cfg(target_os = "linux")]

use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::Path,
};

use argon2::Argon2;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use rand::{rngs::OsRng, RngCore};
use secrecy::{ExposeSecret, SecretString};
use serpent::Serpent;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
type SerpentCbcEnc = Encryptor<Serpent>;
type SerpentCbcDec = Decryptor<Serpent>;

const SALT_LEN: usize = 16;
const IV_LEN: usize = 16;
const TAG_LEN: usize = 32;
const KEY_LEN: usize = 32;

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        return Err("Usage: encrypt|decrypt <file> <password>".into());
    }

    let command = &args[1];
    let path = Path::new(&args[2]);
    let password = SecretString::new(args[3].clone());

    match command.as_str() {
        "encrypt" => encrypt_file(path, &password)?,
        "decrypt" => decrypt_file(path, &password)?,
        _ => return Err("Invalid command".into()),
    }

    Ok(())
}

fn encrypt_file(path: &Path, password: &SecretString) -> Result<(), String> {
    let plaintext = fs::read(path).map_err(|e| e.to_string())?;

    let salt = random_bytes(SALT_LEN);
    let iv = random_bytes(IV_LEN);

    let master = derive_key(password.expose_secret(), &salt)?;
    let (k_enc, k_mac) = derive_subkeys(&master)?;

    let mut buffer = plaintext.clone();
    let msg_len = buffer.len();
    buffer.resize(msg_len + 16, 0u8);

    let ciphertext = SerpentCbcEnc::new_from_slices(&k_enc, &iv)
        .map_err(|e| e.to_string())?
        .encrypt_padded_mut::<Pkcs7>(&mut buffer, msg_len)
        .map_err(|_| "Encryption padding error".to_string())?;

    let mut header = Vec::new();
    header.extend_from_slice(b"SPT2");
    header.extend_from_slice(&salt);
    header.extend_from_slice(&iv);

    let tag = compute_tag(&k_mac, &header, ciphertext)?;

    let mut output = Vec::new();
    output.extend_from_slice(&header);
    output.extend_from_slice(ciphertext);
    output.extend_from_slice(&tag);

    atomic_write(path, &output)?;

    Ok(())
}

fn decrypt_file(path: &Path, password: &SecretString) -> Result<(), String> {
    let file = fs::read(path).map_err(|e| e.to_string())?;

    if file.len() < 4 + SALT_LEN + IV_LEN + TAG_LEN {
        return Err("File too small".into());
    }

    if &file[..4] != b"SPT2" {
        return Err("Invalid format".into());
    }

    let salt = &file[4..4 + SALT_LEN];
    let iv = &file[4 + SALT_LEN..4 + SALT_LEN + IV_LEN];

    let tag_start = file.len() - TAG_LEN;
    let ciphertext = &file[4 + SALT_LEN + IV_LEN..tag_start];
    let tag = &file[tag_start..];

    let master = derive_key(password.expose_secret(), salt)?;
    let (k_enc, k_mac) = derive_subkeys(&master)?;

    verify_tag(&k_mac, &file[..tag_start], ciphertext, tag)?;

    let mut buffer = ciphertext.to_vec();

    let plaintext = SerpentCbcDec::new_from_slices(&k_enc, iv)
        .map_err(|e| e.to_string())?
        .decrypt_padded_mut::<Pkcs7>(&mut buffer)
        .map_err(|_| "Invalid padding".to_string())?;

    atomic_write(path, plaintext)?;

    Ok(())
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let argon2 = Argon2::default();

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("{:?}", e))?;

    Ok(key)
}

fn derive_subkeys(master: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    let hk = Hkdf::<Sha256>::new(None, master);

    let mut enc = [0u8; 32];
    let mut mac = [0u8; 32];

    hk.expand(b"enc", &mut enc)
        .map_err(|e| format!("{:?}", e))?;

    hk.expand(b"mac", &mut mac)
        .map_err(|e| format!("{:?}", e))?;

    Ok((enc, mac))
}

fn compute_tag(key: &[u8], header: &[u8], ciphertext: &[u8]) -> Result<[u8; 32], String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|e| format!("{:?}", e))?;

    mac.update(header);
    mac.update(ciphertext);

    let result = mac.finalize().into_bytes();

    let mut tag = [0u8; 32];
    tag.copy_from_slice(&result);

    Ok(tag)
}

fn verify_tag(
    key: &[u8],
    header: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<(), String> {
    let expected = compute_tag(key, header, ciphertext)?;

    if expected[..] != tag[..] {
        return Err("Authentication failed".into());
    }

    Ok(())
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    buf
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    let tmp_path = path.with_extension("tmp");

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|e| e.to_string())?;

    file.write_all(data).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;

    fs::rename(tmp_path, path).map_err(|e| e.to_string())?;

    Ok(())
}
