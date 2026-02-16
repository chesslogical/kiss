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

const MAGIC: &[u8] = b"SECA1";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        print_usage();
        std::process::exit(1);
    }

    let command = &args[1];
    let filename = &args[2];

    match command.as_str() {
        "enc" => {
            println!("Password:");
            let pass1 = read_password()?;

            println!("Confirm password:");
            let pass2 = read_password()?;

            if pass1 != pass2 {
                return Err("Passwords do not match.".into());
            }

            encrypt_file(filename, &pass1)?;
            println!("OK");
        }
        "dec" => {
            println!("Password:");
            let password = read_password()?;

            decrypt_file(filename, &password)?;
            println!("OK");
        }
        _ => {
            print_usage();
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_usage() {
    println!("Usage:");
    println!("  secureapp enc <file>");
    println!("  secureapp dec <file>");
}

fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], Box<dyn std::error::Error>> {
    let mut key = [0u8; KEY_LEN];

    let params = Params::new(
        65536, // 64 MB memory
        3,     // iterations
        1,     // parallelism
        Some(KEY_LEN),
    )
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
    let mut plaintext = Vec::new();
    File::open(path)?.read_to_end(&mut plaintext)?;

    if plaintext.starts_with(MAGIC) {
        return Err("File already encrypted.".into());
    }

    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let key = derive_key(password, &salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());

    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);

    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|_| "Encryption failed")?;

    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    atomic_replace(path, &output)?;

    Ok(())
}

fn decrypt_file(path: &str, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut data = Vec::new();
    File::open(path)?.read_to_end(&mut data)?;

    if data.len() < MAGIC.len() + SALT_LEN + NONCE_LEN {
        return Err("Invalid file format.".into());
    }

    if &data[..MAGIC.len()] != MAGIC {
        return Err("Not a secureapp encrypted file.".into());
    }

    let salt_start = MAGIC.len();
    let nonce_start = salt_start + SALT_LEN;
    let cipher_start = nonce_start + NONCE_LEN;

    let salt = &data[salt_start..nonce_start];
    let nonce = &data[nonce_start..cipher_start];
    let ciphertext = &data[cipher_start..];

    let key = derive_key(password, salt)?;
    let cipher = XChaCha20Poly1305::new((&key).into());

    let plaintext = cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| "Wrong password or corrupted file")?;

    atomic_replace(path, &plaintext)?;

    Ok(())
}

fn atomic_replace(original: &str, data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let original_path = Path::new(original);

    let temp_path = if let Some(parent) = original_path.parent() {
        if parent.as_os_str().is_empty() {
            PathBuf::from(format!("{}.tmp_secureapp", original))
        } else {
            parent.join(format!(
                "{}.tmp_secureapp",
                original_path
                    .file_name()
                    .ok_or("Invalid filename")?
                    .to_string_lossy()
            ))
        }
    } else {
        PathBuf::from(format!("{}.tmp_secureapp", original))
    };

    {
        let mut temp_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;

        temp_file.write_all(data)?;
        temp_file.sync_all()?;
    }

    fs::rename(&temp_path, &original_path)?;

    let dir_path = original_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));

    let dir = File::open(dir_path)?;
    dir.sync_all()?;

    Ok(())
}
