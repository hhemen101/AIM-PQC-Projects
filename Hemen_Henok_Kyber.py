from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os
import time
import binascii

# Generates 256-bit shared AES key.
def aes_key(kem_key):
    
    return HKDF(algorithm=hashes.SHA256(),
               length=32,
               salt = None,
               info = None,
               backend = default_backend()).derive(kem_key)
            
def kyber(kyber_variant):  

    # Kyber Key Pair Generation.
    start_time = time.time()
    ek, dk = kyber_variant.keygen()
    key_time = time.time() - start_time

    # Encapsulates the shared AES key using the public key.
    start_time = time.time()
    kem_key, ct = kyber_variant.encaps(ek)
    encaps_time = time.time() - start_time
    
    # Decapsulates the shared AES key using the private key.
    start_time = time.time()
    kem_key_decaps = kyber_variant.decaps(dk, ct)
    decaps_time = time.time() - start_time

    # Verifies that the encapsulated and decapsulated keys are the same.
    assert kem_key == kem_key_decaps

    print(f"Key generation time: {key_time:.10f} seconds")
    print(f"Encapsulation time: {encaps_time:.10f} seconds")
    print(f"Decapsulation time: {decaps_time:.10f} seconds")
    print(f"Ciphertext size: {len(ct)} bytes")
    print(f"Shared key size: {len(kem_key)} bytes")

    return kem_key

def aes_encrypt_decrypt(kem_key, message):

    # Generates a random 16-byte Initialization Vector. 
    iv = os.urandom(16)

    # Creates AES encryption and decryption context.
    aes_context= Cipher(algorithms.AES(kem_key),modes.CBC(iv),backend=default_backend())                     
    aes_encrypt = aes_context.encryptor()
    aes_dec = aes_context.decryptor()
    
    # Pads the message to a 128-bit block length then encrypts it.
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()    
    encrypted_message = aes_encrypt.update(padded_message) + aes_encrypt.finalize()
       
    # Decrypts the ciphertext then unpads the decrypted message.
    decrypt_key = aes_dec.update(encrypted_message) + aes_dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_padded = unpadder.update(decrypt_key) + unpadder.finalize()
    
    # Converting the unpadded bytes to a plaintext utf-8 string.
    decrypted_message = decrypted_padded.decode('utf-8')

    return iv, decrypted_message, encrypted_message

def alice_message_exchange(kyber_variant):

    shared_key = kyber(kyber_variant)
    
    # Alice sends a message to Bob.
    alice_message = input("Enter a message: ")
    alice_message_byte = alice_message.encode()

    # Encrpyts Alice's message using the AES encryption context then Bob decrypts the message using the shared key.
    iv, decrypted_message, encrypted_message = aes_encrypt_decrypt(shared_key, alice_message_byte)
    alice_encrypt = binascii.hexlify(encrypted_message).decode()
    print("Alice's message encrypted:", alice_encrypt)
    print("Alice's message decrypted:", decrypted_message)

def bob_message_exchange(kyber_variant):

    shared_key = kyber(kyber_variant)
    
    # Bob sends a message to Alice.
    bob_message = input("Enter a message: ")
    bob_message_byte = bob_message.encode()
        
    # Encrpyts Bob's message using AES encryption and Alice decrypts the message using the shared key.
    iv, decrypted_message, encrypted_message = aes_encrypt_decrypt(shared_key, bob_message_byte)
    bob_encrypt = binascii.hexlify(encrypted_message).decode()
    print("Bob's message encrypted:", bob_encrypt)
    print("Bob's message decrypted:", decrypted_message)

# Lists the various Kyber variants that will be implemented for the secure key exchange process.
name = "Kyber512", "Kyber768", "Kyber1024"
variant = [ML_KEM_512, ML_KEM_768, ML_KEM_1024]

# Iterates through each Kyber variant.
for variant, name in zip(variant, name):
    kyber_variant = variant
    names = name

    print(f"\n Testing: {name}")

# Loops until a valid input is entered.
    while True:

        # Allows the user to choose if Bob or Alice is the sender. 
        sender = input(f"\n Who is the sender - Bob or Alice? ")
    
        if sender == 'Alice':
            alice_message_exchange(kyber_variant)
            break
        elif sender == 'Bob':
            bob_message_exchange(kyber_variant)
            break
        else:
            print("Invalid input. Please pick Alice or Bob.")




