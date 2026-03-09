# Quantum-Resistant Encrypted Chat
This project demonstrates a quantum resistant messaging prototype using Kyber, a post-quantum key encapsulation mechanism (KEM), combined with symmetric encryption using Advanced Encryption Standard (AES). Two parties (Alice and Bob) securely establish a shared secret to send encrypted messages and decrypt them. The simulation is executed 3 times because it iterates through 3 of the Kyber variants to securely establish a shared key.


## Project Overview
- Utilized the Kyber key encapsulation mechanism for secure key exchange.
- Implements 3 variants of Kyber to evaluate and compare the security and processing time.
- Implements AES to generate a 256-bit shared AES key. 


## Technologies used  

### Cryptography.io: 
- Utilized the hazmat subpackage from the cryptography library 
- Employed AES encryption - used the Cipher, algorithms, and modes modules.
- Applied PKCS7 padding - used the padding module.
- Used the HKDF and hashes modules.
- Imported the default_backend from hazmat.backends.

### Kyber (ML_KEM):
- Utilized for secure key exchange.
- Implemented 3 security levels - Kyber512, Kyber768, and Kyber1024. 
- kyber.py - imported the 3 Kyber variants.

### Python libraries
- os library - utilized to generate 16 bytes of secure random data for the Initialization Vector.
- time library - used to record the time taken for key generation, encapsulation, and decapsulation process.
- binascii library - used to convert the ciphertext from binary to hexadecimal format.


## Project Structure and Logic

### Message Exchange Process
Alice or Bob can act as the sender.
1. Sender inputs a message. 
2. The message gets encrypted using the shared AES key.
3. The encrypted message is converted from the raw encrypted bytes to hexadecimal, then decoded to convert the byte object to a regular string.
4. Receiver decrypts the message using the shared AES key.

### Key Exchange Process
1. A Kyber key pair is generated.
2. Records the time it took for Kyber key generation.  
3. The shared AES key is encapsulated using the public key.
4. Shared key passed through HMAC-based Extract-and-Expand Key Derivation Function (HKDF) with SHA-256 to derive an AES 256-bit key.
5. Records the time it took for the encapsulation process. 
6. The private key is used to decapsulate the shared AES key.
7. Records the time it took for the decapsulation process. 
8. Verifies that the encapsulated and decapsulated shared AES key have the same value.
9. Displays the time spent on key generation encapsulation, and decapsulation in seconds.
10. Displays the ciphertext and shared key size in bytes.


### Encryption Process
1. Generates a random 16-byte Initialization Vector to prevent identical ciphertexts.
2. Uses the Cipher module to create the encryption engine.
3. AES is used to encrypt the message using the shared key.
4. Utilizes Cipher Block Chaining (CBC) to chain encrypted blocks together using the Initialization Vector to add randomness.
5. Uses the default backend as the cryptographic engine to perform low-level cryptographic operations efficiently.
6. Creates a PKCS7 padder and pads the message to a 128-bit block length to make the plaintext the correct size for block encryption.
7. Encrypts the padded message using the AES encryption context.


### Decryption Process
1. Uses the Cipher module to create the decryption engine.
2. Decrypts the encrypted message using the AES decryption context.
3. Unpads the decrypted message to remove the extra bytes that were added during padding so the original plaintext message can be recovered.
4. Converts the unpadded message to a plaintext UTF-8 string.

## How to Run
Be in the root directory
### Prerequisites
```bash
git clone https://github.com/hhemen101/AIM-PQC-Projects.git
```
```bash
python AIM-PQC-Projects\Quantum-Resistant Encrypted Chat\Kyber.py
```

## Key Findings
- Kyber1024 - maximum security with a greater ciphertext size, but slower processing time.
- Kyber768 - moderate performance and security.
- Kyber512 - fastest key generation, encapsulation, and decapsulation time, but at the cost of reduced security margins.

## Benefits of combining post-quantum cryptography with symmetric encryption: 
- Hybrid strength - ensures comprehensive security over various cryptographic algorithms.
- Multi-layered defense - if one layer of the PQC implementation is attacked, symmetric encryption still protects the actual data.
- Allows for a smooth transition to quantum-safe protocols - can easily integrate PQC into symmetric encryption-based systems.
- Forward Secrecy - ensures past communications remain secure even if encryption keys are compromised in the future.