# -*- coding: utf-8 -*-

# pip install cryptography

# pip install pycryptodome
import secrets
import base64
import hashlib
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Function to encrypt a string using AES in CBC mode with PKCS7 padding and return the result as a Base64-encoded string
def aesEncryptToBase64(clear_text, key_base64):
    key = base64.b64decode(key_base64)
    iv = b'\x00' * 16
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_text = clear_text.encode() + (AES.block_size - len(clear_text) % AES.block_size) * chr(AES.block_size - len(clear_text) % AES.block_size).encode()
    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted).decode()

def stringToBase64(my_string):
    my_string_bytes = my_string.encode('ascii')
    padding = len(my_string_bytes) % 4
    if padding > 0:
        my_string_bytes += b'=' * (4 - padding)
    base64_bytes = base64.b64encode(my_string_bytes)
    base64_string = base64_bytes.decode('ascii')
    return base64_string

def aes_ctr_256_encrypt(plaintext, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return base64.b64encode(ciphertext)

def aes_ctr_256_decrypt(ciphertext, key, nonce):
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
    return plaintext


# key = secrets.token_bytes(32)
# iv = b'\x00' * 16
# plaintext = b'This is a sample plaintext to encrypt using AES CTR mode.'
# nonce = secrets.token_bytes(16)

# ciphertext = aes_ctr_256_encrypt(plaintext, key, nonce)
# print("Encrypted : " + ciphertext.decode('utf-8')) 
# print("iv = " + str(len(iv)))
# print("Decrypted : " + aes_ctr_256_decrypt(ciphertext, key, nonce).decode('utf-8'))
