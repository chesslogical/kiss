# kiss  encryption 


Keep It Simple Stupid (kiss) method. dead simple cli encryption apps. 

Each folder is its own app. 

Most have ONE command (the file name to encrypt) . Automatically encrypts or decrypts the file in place. 

Made ONLY for linux. That is because atomic overwrite options are a bit different in linux than windows or mac.

Modern high security algos !!  The code in here would take someone an incredible level of skill and lots of time to dev- ai made each app in about 4 minutes each
on average, i just fed back the error messages till it passed the strict rust compiler. A few years ago, one could only dream of a repo like this. Code is in main.rs in every app, so it is incredibly easy to feed to ai to audit and update. 

The code is simple but incredibly powerful. It is decent- very much so as is- but it is made to be flexible, able to be updated easily. I do not think one could ask for more from an encryption app. 



s1 AES-256-GCM-SIV key file 

s2  AES-256-GCM-SIV password version
threefish_encrypt is a command-line interface (CLI) tool developed in Rust for encrypting and decrypting files using the Threefish-1024 block cipher in CTR (Counter) mode, combined with HMAC-SHA512 for integrity and authenticity checks. Designed for simplicity, it requires only the filename as input (e.g., ./threefish_encrypt myfile.txt) and operates on files in the same directory as the executable, automatically determining whether to encrypt or decrypt based on a magic header ("TF1024ENC" as 9 bytes) at the file's beginning—if present, it decrypts; otherwise, it encrypts. During encryption, the tool generates a random 16-byte initialization vector (IV), encrypts the content, computes a 64-byte HMAC tag over the header, IV, and ciphertext, and formats the output as header + IV + ciphertext + tag. For decryption, it extracts the IV and tag, verifies the HMAC (failing on tampering or incorrect key), and decrypts to plaintext. Operations are in-place with atomic overwrites via a temporary file to avoid data corruption, and the encryption key is hard-coded as a 128-byte array in the source code (editable at compile time for versatility, but users should replace the default demonstration key with a securely generated random one, such as via openssl rand 128, and recompile). The tool leverages dependencies including threefish (0.5), cipher (0.4), clap (4.5 with derive), anyhow (1.0), rand (0.8), hmac (0.12), and sha2 (0.10) for cryptographic operations, argument parsing, error management, and randomness. While suitable for secure file handling with its robust cipher and authentication, it processes files entirely in memory (limiting use with very large files), lacks password derivation, and emphasizes that hard-coding keys reduces portability and increases security risks if the binary is shared—ideal for personal or embedded use cases where recompilation is feasible.
s3 xor transformer otp operations

s4 Algorithm Choice: XChaCha20-Poly1305 is secure for file encryption (IND-CCA2 secure, resistant to nonce misuse due to extended nonce). uses key

s5 password version of s4 

s6 threefish 256 algo uses key file 

s7 threefish 1024 algo uses key file 

s8 it is s7 in password mode

s9 it is s7 but key is hard coded at compile time. Key is editable at compile time, which makes the app versatile. 
