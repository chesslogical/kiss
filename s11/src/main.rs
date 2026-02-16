use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use rand::RngCore;
use rpassword::read_password;

use argon2::{Argon2, Params};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce,
};

const MAGIC: &[u8] = b"SECA2";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const CHUNK_SIZE: usize = 1024 * 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        println!("Usage: secureapp <file>");
        std::process::exit(1);
    }

    let filename = &args[1];

    if is_encrypted(filename)? {
        println!("Password:");
        let password = read_password()?;
        decrypt_file(filename, &password)?;
    } else {
        println!("Password:");
        let p1 = read_password()?;
        println!("Confirm password:");
        let p2 = read_password()?;

        if p1 != p2 {
            return Err("Passwords do not match.".into());
        }

        encrypt_file(filename, &p1)?;
    }

    println!("OK");
    Ok(())
}

fn is_encrypted(path: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 5];

    if file.read(&mut magic)? != 5 {
        return Ok(false);
    }

    Ok(&magic == MAGIC)
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], Box<dyn std::error::Error>> {
    let mut key = [0u8; KEY_LEN];

    let params = Params::new(65536, 3, 1, Some(KEY_LEN))
        .map_err(|e| format!("Argon2 param error: {:?}", e))?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params,
    );

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Argon2 failure: {:?}", e))?;

    Ok(key)
}

fn encrypt_file(path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = File::open(path)?;

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());

    let mut nonce_base = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_base);

    let temp_path = temp_path(path);
    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)?;

    output.write_all(MAGIC)?;
    output.write_all(&[VERSION])?;
    output.write_all(&salt)?;
    output.write_all(&nonce_base)?;
    output.write_all(&(CHUNK_SIZE as u32).to_le_bytes())?;

    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut counter: u64 = 0;

    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }

        let mut nonce = nonce_base;
        nonce[16..24].copy_from_slice(&counter.to_le_bytes());

        let encrypted = cipher
            .encrypt(XNonce::from_slice(&nonce), &buffer[..read])
            .map_err(|_| "Encryption failure")?;

        output.write_all(&(encrypted.len() as u32).to_le_bytes())?;
        output.write_all(&encrypted)?;

        counter += 1;
    }

    output.sync_all()?;
    finalize_atomic(path, &temp_path)?;

    Ok(())
}

fn decrypt_file(path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = File::open(path)?;

    let mut magic = [0u8; 5];
    input.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("Not a secureapp file.".into());
    }

    let mut version = [0u8; 1];
    input.read_exact(&mut version)?;

    let mut salt = [0u8; SALT_LEN];
    input.read_exact(&mut salt)?;

    let mut nonce_base = [0u8; NONCE_LEN];
    input.read_exact(&mut nonce_base)?;

    let mut chunk_size_bytes = [0u8; 4];
    input.read_exact(&mut chunk_size_bytes)?;
    let _ = u32::from_le_bytes(chunk_size_bytes);

    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());

    let temp_path = temp_path(path);
    let mut output = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)?;

    let mut counter: u64 = 0;

    loop {
        let mut len_bytes = [0u8; 4];

        if input.read(&mut len_bytes)? == 0 {
            break;
        }

        let chunk_len = u32::from_le_bytes(len_bytes) as usize;

        let mut encrypted = vec![0u8; chunk_len];
        input.read_exact(&mut encrypted)?;

        let mut nonce = nonce_base;
        nonce[16..24].copy_from_slice(&counter.to_le_bytes());

        let decrypted = cipher
            .decrypt(XNonce::from_slice(&nonce), encrypted.as_ref())
            .map_err(|_| "Wrong password or corrupted file")?;

        output.write_all(&decrypted)?;
        counter += 1;
    }

    output.sync_all()?;
    finalize_atomic(path, &temp_path)?;

    Ok(())
}

fn temp_path(original: &str) -> PathBuf {
    PathBuf::from(format!("{}.tmp_secureapp", original))
}

fn finalize_atomic(original: &str, temp: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::rename(temp, original)?;

    let parent = Path::new(original)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));

    let dir = File::open(parent)?;
    dir.sync_all()?;

    Ok(())
}
