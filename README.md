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

s3 xor transformer otp operations

s4 Algorithm Choice: XChaCha20-Poly1305 is secure for file encryption (IND-CCA2 secure, resistant to nonce misuse due to extended nonce). uses key

s5 password version of s4 

s6 threefish 256 algo uses key file 

s7 threefish 1024 algo uses key file 

s8 it is s7 in password mode

s9 it is s7 but key is hard coded at compile time. Key is editable at compile time, which makes the app versatile. 
