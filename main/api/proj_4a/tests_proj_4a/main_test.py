"""
-*- coding: utf-8 -*-
Implementation of the Encryption Utility
Created: April 2023
Owners: Project 4a: Muskaan Manocha, Prem Desai, Yeshaswini Murthy
"""

import logging
import unittest
import sys
 
# setting path
sys.path.append('../proj_4a')
 
# importing
from encryption_util import *

class TestEncryptionUtil(unittest.TestCase):

    def setUp(self):
        self.encryption_util = EncryptionUtil()

    def test_aes_encryption_decryption(self):
        key = b64decode(self.encryption_util.generateAESKeyBase64())
        plain_text = 'This is a secret message'
        encrypted_text = self.encryption_util.aesEncryptToBase64(plain_text, b64encode(key).decode('utf-8'))
        decrypted_text = self.encryption_util.aesDecryptFromBase64(encrypted_text, b64encode(key).decode('utf-8'))
        self.assertEqual(decrypted_text, plain_text)

    def test_rsa_encryption_decryption(self):
        key_pair = self.encryption_util.generateRSAKeyPair()
        public_key = key_pair.publickey().export_key()
        private_key = key_pair.export_key()
        plain_text = 'This is a secret message'
        encrypted_text = self.encryption_util.rsaEncryptToBase64(plain_text, b64encode(public_key).decode('utf-8'))
        decrypted_text = self.encryption_util.rsaDecryptFromBase64(encrypted_text, b64encode(private_key).decode('utf-8'))
        self.assertEqual(decrypted_text, plain_text)

    def test_sign_sha256_rsa(self):
        key_pair = self.encryption_util.generateRSAKeyPair()
        private_key = key_pair.export_key()
        public_key = key_pair.publickey().export_key()
        data = b'This is some data to sign'
        hashed_data = SHA256.new(data)
        signature = self.encryption_util.signSHA256RSA(hashed_data, private_key)
        verifier = pkcs1_15.new(RSA.import_key(public_key))
        self.assertTrue(verifier.verify(hashed_data, signature))

    
import logging
import unittest
import binascii
import secrets
import base64
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from cryptography.hazmat.primitives import padding
from aes_encryption import *
from rsa_encryption import *
from encryption_util import *

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)s %(message)s')

class TestEncryptionUtil(unittest.TestCase):
    def setUp(self):
        self.util = EncryptionUtil()
        logging.basicConfig(level=logging.INFO)

    def test_nonce(self):
        logging.info("Util.nonce is initialized to None: %s", self.util.nonce)
        self.assertIsNone(self.util.nonce)
        self.util.nonce = 16
        logging.info("Util.nonce is updated to: %s", self.util.nonce)
        self.assertIsNotNone(self.util.nonce)

    def test_generate_aes_key_base64(self):
        key = self.util.generateAESKeyBase64()
        self.assertIsNotNone(key)
        logging.info("Generated AES key: %s", key)

    def test_rsa_keypair(self):
        self.assertEqual(len(self.util.rsa_keypair), 2)
        logging.info("Util.rsa_keypair is initialized to None: %s", self.util.rsa_keypair)
        self.assertIsNone(self.util.rsa_keypair)
        self.util.rsa_keypair = self.generate_key_pair(bytes)
        logging.info("Util.rsa_keypair is updated to: %s", self.util.rsa_keypair)
        self.assertIsNotNone(self.util.rsa_keypair)
        self.assertEqual(len(self.util.rsa_keypair), 2)

    def test_aes_encrypt_decrypt(self):
        plaintext = "Hello World!!! 1234" # testing with multiple types of characters
        key = self.util.generateAESKeyBase64()
        logging.info("Encrypting %s using AES key %s", (plaintext, key))
        encrypted = self.util.aesEncryptFromBase64(plaintext, key)
        logging.info("Decrypting %s using AES key %s", (encrypted, key))
        decrypted = self.util.aesDecryptFromBase64(encrypted, key)
        logging.info("Comparing decrypted text %s with original %s%s", (decrypted, plaintext))
        self.assertEqual(plaintext, decrypted)

    def test_rsa_encrypt_decrypt(self):
        plaintext = "Hello World!!! 1234" # testing with multiple types of characters
        pubkey = self.util.publicKeyFromBase64()
        privkey = self.util.privateKeyFromBase64()
        logging.info("Original text: %s, encrypting using privkey %s", (clear_text, pubkey))
        encrypted = self.util.rsaEncryptToBase64(plaintext, pubkey)
        logging.info("Encrypted text: %s, decrypting using %s", (encrypted_text, privkey))
        self.assertIsNotNone(encrypted_text)
        decrypted = self.util.rsaDecryptFromBase64(encrypted, privkey)
        logging.info("Decrypted text: %s", decrypted_text)
        self.assertEqual(plaintext, decrypted)

    def test_sign_verify(self):
        data = b"Hello World!!! 1234" # testing with multiple types of characters
        privkey = self.util.privateKeyFromBase64()
        signature = self.util.signSHA256RSA(data, privkey)
        pubkey = self.util.publicKeyFromBase64()
        self.assertTrue(self.util.verifySHA256RSA(data, signature, pubkey))

    def test_aes_decrypt_invalid_key(self):
        """negative test"""
        plaintext = "hello world"
        key = self.util.generateAESKeyBase64()
        encrypted = self.util.aesEncryptFromBase64(plaintext, key)
        invalid_key = self.util.generateAESKeyBase64()
        with self.assertRaises(ValueError):
            decrypted = self.util.aesDecryptFromBase64(encrypted, invalid_key)

    def test_rsa_decrypt_invalid_key(self):
        """negative test"""
        plaintext = "hello world"
        pubkey = self.util.publicKeyFromBase64()
        privkey = self.util.privateKeyFromBase64()
        encrypted = self.util.rsaEncryptToBase64(plaintext, pubkey)
        invalid_key = self.util.privateKeyFromBase64()
        with self.assertRaises(ValueError):
            decrypted = self.util.rsaDecryptFromBase64(encrypted, invalid_key)

if __name__ == '__main__':
    unittest.main()
    