# SecureFileSphere

**SecureFileSphere** is a robust file encryption tool built in C that allows users to encrypt files using multiple cryptographic algorithms. It supports the following encryption methods:

- **RC4** (Rivest Cipher 4)
- **AES** (Advanced Encryption Standard)
- **DES** (Data Encryption Standard)
- **3-DES** (Triple DES)
- **Salsa20** (Stream Cipher)

This project aims to provide a secure and flexible solution for file encryption, making it easy for users to protect their sensitive data using various encryption techniques.

## Makefile Overview

The provided Makefile automates the process of compiling, running, and cleaning up the project. It has four primary targets:

    all: Default target that will run the program after compiling.
    run: Runs the compiled encryption program.
    compile: Compiles the main.c file into an executable program named encryption_program.
    clean: Removes all *.bin files (all encrypted files)
    clean_all: Removes all *.bin files and the encryption_program executable.


---

## Features

- **Multiple Encryption Algorithms**: SecureFileSphere supports five popular encryption algorithms:
  - **RC4**: A symmetric stream cipher.
  - **AES**: A symmetric block cipher with 128, 192, and 256-bit key sizes.
  - **DES**: A symmetric block cipher using a 56-bit key.
  - **3-DES**: An enhanced version of DES with 3 layers of encryption.
  - **Salsa20**: A high-speed stream cipher designed for efficiency.

- **File Encryption and Decryption**: Easily encrypt and decrypt files with a specified encryption algorithm.

- **Custom Output File Naming**: The output file is automatically named based on the input file and the encryption algorithm used (e.g., `demo.txt_encrypted_AES.txt`).

---

## Algorithm Descriptions

### 1. **RC4 (Rivest Cipher 4)**

RC4 is a symmetric stream cipher that encrypts data one byte at a time. It uses a variable-length key to initialize an internal state, which is then used to generate a keystream that is XORed with the plaintext.

### 2. **AES (Advanced Encryption Standard)**

AES is a block cipher that operates on fixed-size blocks of data (128 bits). It supports key sizes of 128, 192, and 256 bits, providing robust security for data encryption. AES is widely used for government and commercial encryption.

### 3. **DES (Data Encryption Standard)**

DES is an older symmetric block cipher that uses a 56-bit key. Though considered insecure today due to its small key size, it is still used for educational purposes and historical reference.

### 4. **3-DES (Triple DES)**

3-DES is a more secure variant of DES that applies the DES algorithm three times to each data block, using either two or three different keys. This enhances security compared to standard DES.

### 5. **Salsa20**

Salsa20 is a high-speed stream cipher that encrypts data byte-by-byte. It is known for its simplicity and security, making it a popular choice for modern cryptographic applications.

---

## License

**SecureFileSphere** is licensed under the [MIT License](LICENSE). See the LICENSE file for more details.

---

## Acknowledgments

- **OpenSSL**: A robust and widely-used library for cryptographic functions.
- **libsodium**: A high-level cryptographic library that provides easy-to-use cryptographic primitives, including Salsa20.