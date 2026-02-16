# kiss  encryption 


Keep It Simple Stupid (kiss) method. dead simple cli encryption apps. 

Each folder is its own app. 

ONE command for each app  (the file name to encrypt) . Automatically encrypts or decrypts the file in place. 

Made ONLY for linux. That is because atomic overwrite options are a bit different in linux than windows or mac



s1 and s2  AES-256-GCM-SIV

s3 xor transformer otp like 


s4 Algorithm Choice: XChaCha20-Poly1305 is secure for file encryption (IND-CCA2 secure, resistant to nonce misuse due to extended nonce). uses key

s5 password version of s4 
