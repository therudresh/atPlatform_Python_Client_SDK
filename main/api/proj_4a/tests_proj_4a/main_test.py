"""
-*- coding: utf-8 -*-
Implementation of the Encryption Utility Test File
Created: April 2023
Owners: Project 4a: Muskaan Manocha, Prem Desai, Yeshaswini Murthy
"""

import logging
import unittest
import sys
import os

# getting the name of the directory
# where the this file is present.
current = os.path.dirname(os.path.realpath(__file__))
 
# Getting the parent directory name
# where the current directory is present.
parent = os.path.dirname(current)
 
# adding the parent directory to
# the sys.path.
sys.path.append(parent)
 
# now we can import the module in the parent
# directory.
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
        Test that nonce is set after calling the setter, and verify it is not None.
        """
        logging.info("Util.nonce is initialized to: %s", self.util.nonce)
        self.assertIsNotNone(self.util.nonce)

    def test_rsa_keypair(self):
        """
        Test that the length of rsa_keypair is 2, and verify that it is initialized to None, then set to a non-None value after setter is called
        """
        self.assertIsNone(self.util.rsa_keypair)
        logging.info("Util.rsa_keypair is initialized to None: %s", self.util.rsa_keypair)
        keypair = self.util.generateRSAKeyPair()  # using setter function
        logging.info("keypair after generation is:")
        logging.info(keypair)
        logging.info("Util.rsa_keypair is updated to:")
        logging.info(self.util.rsa_keypair)
        self.assertIsNotNone(self.util.rsa_keypair)
        self.assertEqual(len(self.util.rsa_keypair), 2)

    # def test_generate_aes_key_base64(self):
    #     """
    #     Test that a non-None AES key is generated and logged.
    #     """
    #     key = self.util.generateAESKeyBase64()
    #     self.assertIsNotNone(key)
    #     logging.info("Generated AES key: %s", key)

    # def test_aes_encrypt_decrypt(self):
    #     """
    #     Test AES encryption and decryption, verify that decrypted text is equal to original plaintext.
    #     """
    #     plaintext = "Hello World!!! 1234"
    #      # testing with multiple types of characters
    #     key = self.util.generateAESKeyBase64()
    #     logging.info("Encrypting %s using AES key %s", (plaintext, key))
    #     encrypted = self.util.aesEncryptFromBase64(plaintext, key)
    #     logging.info("Decrypting %s using AES key %s", (encrypted, key))
    #     decrypted = self.util.aesDecryptFromBase64(encrypted, key)
    #     logging.info("Comparing decrypted text %s with original %s%s", (decrypted, plaintext))
    #     self.assertEqual(plaintext, decrypted)

    def test_rsa_encrypt_decrypt(self):
        """
        Test RSA encryption and decryption, verify that decrypted text is equal to original plaintext.
        """
        plaintext = "Hello World!!! 1234" # testing with multiple types of characters
        keypair = self.util.generateRSAKeyPair()
        logging.info("keypair after generation is")
        logging.info(keypair)
        pubkey = self.util.publicKeyFromBase64()
        privkey = self.util.privateKeyFromBase64()
        logging.info("Type of the generated public key and private key are: %s and %s respectively" % (type(pubkey), type(privkey)))
        self.assertEqual(str(type(privkey)), "<class 'rsa.key.PrivateKey'>")
        self.assertEqual(str(type(pubkey)), "<class 'rsa.key.PublicKey'>")
        logging.info("Original text: %s, encrypting using privkey:" % plaintext)
        logging.info(privkey)
        encrypted = self.util.rsaEncryptToBase64(plaintext, pubkey)
        logging.info("Encrypted text: %s, decrypting using" % encrypted)
        logging.info("privkey")
        self.assertIsNotNone(encrypted)
        decrypted = self.util.rsaDecryptFromBase64(encrypted, privkey)
        logging.info("Decrypted text: %s", decrypted)
        self.assertEqual(plaintext, decrypted)
        print(pubkey)


    # def test_sign_verify(self):
    #     """
    #     Test SHA256RSA signing and verification with a non-None signature.
    #     """
    #     data = b"Hello World!!! 1234" # testing with multiple types of characters
    #     privkey = self.util.privateKeyFromBase64()
    #     signature = self.util.signSHA256RSA(data, privkey)
    #     pubkey = self.util.publicKeyFromBase64()
    #     self.assertTrue(self.util.verifySHA256RSA(data, signature, pubkey))

    # def test_aes_decrypt_invalid_key(self):
    #     """negative test"""
    #     plaintext = "hello world"
    #     key = self.util.generateAESKeyBase64()
    #     encrypted = self.util.aesEncryptFromBase64(plaintext, key)
    #     invalid_key = self.util.generateAESKeyBase64()
    #     with self.assertRaises(ValueError):
    #         decrypted = self.util.aesDecryptFromBase64(encrypted, invalid_key)

    # def test_rsa_decrypt_invalid_key(self):
    #     """negative test"""
    #     keypair = self.util.generateRSAKeyPair() # generate key pair
    #     logging.info("keypair after generation is %s" % keypair)
    #     plaintext = "hello world"
    #     pubkey = self.util.publicKeyFromBase64()
    #     privkey = self.util.privateKeyFromBase64()
    #     encrypted = self.util.rsaEncryptToBase64(plaintext, pubkey)
    #     invalid_key = self.util.privateKeyFromBase64()
    #     with self.assertRaises(ValueError):
    #         decrypted = self.util.rsaDecryptFromBase64(encrypted, invalid_key)

if __name__ == '__main__':
    unittest.main()
