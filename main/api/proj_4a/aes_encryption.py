"""
-*- coding: utf-8 -*-
Implementation class of the AES Encryption and decryption operations.
Created: April 2023
Owners: Project 4a: Muskaan Manocha, Prem Desai, Yeshaswini Murthy
"""

# pip install cryptography
# pip install pycryptodome

import secrets
import base64
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from encryption import Encryption

class AesEncryption(Encryption):

    def __init__(self):
        self.iv = b'\x00' * 16
        self.key = base64.b64decode(key_base64)

    def encrypt(self, plaintext, key, nonce):
         """
        Encrypts the given plaintext using AES in CTR mode with a 256-bit key and returns
        the result as a Base64-encoded string.

        :param plaintext: The plaintext to encrypt.
        :type plaintext: bytes
        :param key: The encryption key.
        :type key: bytes
        :param nonce: The nonce value.
        :type nonce: bytes
        :return: The Base64-encoded ciphertext.
        :rtype: bytes
        """
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return base64.b64encode(ciphertext).decode()

    def decrypt(self, ciphertext, key, nonce):
        """
        Decrypts the given ciphertext using AES in CTR mode with a 256-bit key and returns
        the result as a bytes object.

        :param ciphertext: The Base64-encoded ciphertext to decrypt.
        :type ciphertext: str
        :param key: The encryption key.
        :type key: bytes
        :param nonce: The nonce value.
        :type nonce: bytes
        :return: The plaintext.
        :rtype: bytes
        """
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
        return plaintext

    def encrypt_to_base64(self, clear_text, key_base64):
        """
        Encrypts the given plaintext using AES in CBC mode with PKCS7 padding and returns
        the result as a Base64-encoded string.

        :param clear_text: The plaintext to encrypt.
        :type clear_text: str
        :param key_base64: The Base64-encoded encryption key.
        :type key_base64: str
        :return: The Base64-encoded ciphertext.
        :rtype: str
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        padded_text = clear_text.encode() + (AES.block_size - len(clear_text) % AES.block_size) * 
        chr(AES.block_size - len(clear_text) % AES.block_size).encode()
        encrypted = cipher.encrypt(padded_text)
        return base64.b64encode(encrypted).decode()

    def decrypt_base64(self, encrypted_text, key_base64):
        """
        Converts the given string to a Base64-decoded string.

        :param my_string: The string to decode.
        :type my_string: str
        :return: The Base64-decoded string.
        :rtype: str
        """
        cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
        return decrypted.decode().rstrip(chr(AES.block_size - ord(decrypted[-1])))
    