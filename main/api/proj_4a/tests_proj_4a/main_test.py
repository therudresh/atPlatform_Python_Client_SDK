"""
-*- coding: utf-8 -*-
Implementation of the Encryption Utility Test File
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
        """
        Set up test case by initializing EncryptionUtil instance and setting up logging.
        """
        self.util = EncryptionUtil()
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

    def tearDown(self):
        """
        Tear down test case.
        """
        pass

    def test_nonce(self):
        """
        Test that nonce is initialized to None, then set to secrets.token_bytes(16), and verify it is not None.
        """
        logging.info("Util.nonce is initialized to None: %s", self.util.nonce)
        self.assertIsNone(self.util.nonce)
        self.util.nonce = secrets.token_bytes(16)
        logging.info("Util.nonce is updated to: %s", self.util.nonce)
        self.assertIsNotNone(self.util.nonce)

    def test_generate_aes_key_base64(self):
        """
        Test that a non-None AES key is generated and logged.
        """
        key = self.util.generateAESKeyBase64()
        self.assertIsNotNone(key)
        logging.info("Generated AES key: %s", key)

    def test_rsa_keypair(self):
        """
        Test that the length of rsa_keypair is 2, and verify that it is initialized to None, then set to a non-None value.
        """
        self.assertEqual(len(self.util.rsa_keypair), 2)
        logging.info("Util.rsa_keypair is initialized to None: %s", self.util.rsa_keypair)
        self.assertIsNone(self.util.rsa_keypair)
        self.util.rsa_keypair = self.generate_key_pair(bytes)
        logging.info("Util.rsa_keypair is updated to: %s", self.util.rsa_keypair)
        self.assertIsNotNone(self.util.rsa_keypair)
        self.assertEqual(len(self.util.rsa_keypair), 2)

    def test_aes_encrypt_decrypt(self):
        """
        Test AES encryption and decryption, verify that decrypted text is equal to original plaintext.
        """
        plaintext = "Hello World!!! 1234" # testing with multiple types of characters
        key = self.util.generateAESKeyBase64()
        logging.info("Encrypting %s using AES key %s", (plaintext, key))
        encrypted = self.util.aesEncryptFromBase64(plaintext, key)
        logging.info("Decrypting %s using AES key %s", (encrypted, key))
        decrypted = self.util.aesDecryptFromBase64(encrypted, key)
        logging.info("Comparing decrypted text %s with original %s%s", (decrypted, plaintext))
        self.assertEqual(plaintext, decrypted)

    def test_rsa_encrypt_decrypt(self):
        """
        Test RSA encryption and decryption, verify that decrypted text is equal to original plaintext.
        """
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
        """
        Test SHA256RSA signing and verification with a non-None signature.
        """
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
