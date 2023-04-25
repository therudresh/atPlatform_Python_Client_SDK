"""
-*- coding: utf-8 -*-
Implementation of the Encryption Utility
Created: April 2023
Owners: Project 4a: Muskaan Manocha, Prem Desai, Yeshaswini Murthy
"""
import base64
import os
import binascii
import secrets
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from cryptography.hazmat.primitives import padding
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from aes_encryption import *
from rsa_encryption import *

class EncryptionUtil(AesEncryption, RsaEncryption):

    """
    Utility Methods:
    __init__() : Initializes the nonce and RSA keypair so that we can use the properties/setters accordingly
    nonce() : Getter for the nonce
    nonce(bytes=16) : Setter for the nonce, accepts number of bytes to generate
    rsa_keypair() : Getter for the RSA keypair
    rsa_keypair(bytes=2048) : Setter for the RSA keypair, accepts number of bytes to generate
    aesDecryptFromBase64(clearText, keyBase64) : Decrypts clearText using the provided keyBase64
    aesEncryptToBase64(plainText, keyBase64) : Encrypts plainText using the provided keyBase64
    generateAESKeyBase64() : Generates a new AES key and returns it as a base64 encoded string
    rsaDecryptFromBase64(cipherText, privateKeyBase64) : Decrypts cipherText using the provided privateKeyBase64
    rsaEncryptToBase64(clearText, publicKeyBase64) : Encrypts clearText using the provided publicKeyBase64 and returns
                                                     it as a base64 encoded string
    signSHA256RSA(input_data, private_key) : Generates a SHA256 hash of input_data and signs it with the provided
                                             private_key using PKCS1_v1.5 padding
    generateRSAKeyPair() : Generates a new RSA keypair and returns it
    publicKeyFromBase64() : Returns the RSA public key as a base64 encoded string
    privateKeyFromBase64() : Returns the RSA private key as a base64 encoded string
    """
    
    def __init__(self):
        """
        Initializes the nonce and RSA keypair
        """
        super().__init__()
        self._nonce = None
        self._rsa_keypair = ()

    @property
    def nonce(self):
        """
        Returns the nonce
        """
        return self._nonce
	
    @nonce.setter
    def nonce(self, bytes=16):
        """
        Sets the nonce
        Parameters:
        bytes(int): number of bytes to generate, defaults to 16
        """
        self._nonce = secrets.token_bytes(16)

    @property
    def rsa_keypair(self):
        """
        Returns the RSA keypair
        """
        return self._rsa_keypair
	
    @rsa_keypair.setter
    def rsa_keypair(self, bytes=2048):
        """
        Sets the RSA keypair
        Parameters:
        bytes(int): number of bytes to generate, defaults to 2048
        """
        self._rsa_keypair = self.generate_key_pair(bytes)
    
    def aesEncryptToBase64(self, clearText, keyBase64):
        """
        Decrypts clearText using the provided keyBase64
        Parameters:
        clearText(str): The text to decrypt
        keyBase64(str): The key to use for decryption, as a base64 encoded string
        """
        return AesEncryption.encrypt(self, clearText, keyBase64, self._nonce)
        
    def aesDecryptFromBase64(self, encryptedText, selfEncryptionKey):

        """
        Decrypts the encrypted text using AES decryption with the given key.

        :param encryptedText: The text to be decrypted, as a base64 encoded string.
        :param selfEncryptionKey: The key to be used for decryption, as a base64 encoded string.
        :return: The decrypted plaintext.
        """
        ciphertext = base64.b64decode(encryptedText)
        key = base64.b64decode(selfEncryptionKey)

        plaintext = AesEncryption.decrypt(self, ciphertext, key, self._nonce)

        # Unpad the plaintext using PKCS7 padding
        padder = padding.PKCS7(AES.block_size).unpadder()
        plaintext = padder.update(plaintext) + padder.finalize()

        # Print the decrypted plaintext
        return plaintext.decode('utf-8')

        
    

    @staticmethod
    def generate_aes_key():
        """
        Generates a random AES key of the specified length (in bits).
        The default length is 256 bits.
        """
        key = secrets.token_bytes(32)
        key_base64 = base64.b64encode(key).decode()
        return key_base64
    
    @staticmethod
    def generate_aes_key_str(key_str):
        """
        Generates an AES key using a string as input.
        The key is derived from the input string using a key derivation function.
        """
        # Convert the input string to bytes
        key_bytes = key_str.encode('utf-8')
        iv = b'\x00' * 16
        key = PBKDF2(key_bytes, iv, 32, 1000)
        return key
    
    def rsaDecryptFromBase64(self, cipherText, privateKeyBase64):
        """
        Decrypts the cipher text using RSA decryption with the given private key.

        :param cipherText: The cipher text to be decrypted, encoded in base64.
        :type cipherText: str
        :param privateKeyBase64: The private key to be used for decryption, encoded in base64.
        :type privateKeyBase64: str
        :return: The decrypted plain text.
        :rtype: str
        """
        return RsaEncryption.decrypt(self, cipherText, privateKeyBase64)
        
    def rsaEncryptToBase64(self, clearText, publicKeyBase64):
        """
        Encrypts the clear text using RSA encryption with the given public key.

        :param clearText: The clear text to be encrypted.
        :type clearText: str
        :param publicKeyBase64: The public key to be used for encryption, encoded in base64.
        :type publicKeyBase64: str
        :return: The encrypted cipher text, encoded in base64.
        :rtype: str
        """
        return RsaEncryption.encrypt(self, clearText, publicKeyBase64)

    def signSHA256RSA(self, input_data, private_key):
        """
        Generates a SHA256 hash of the input data and signs it with the provided private key using PKCS1_v1.5 padding.

        :param input_data: The input data to be signed.
        :param private_key: The private key to be used for signing.
        :return: The signature as bytes.
        """
        hash_obj = SHA256.new(input_data.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return signature


    def generateRSAKeyPair(self):
        """
        Generates a new RSA key pair.

        :return: The generated RSA key pair, consisting of a public key and a private key.
        :rtype: Tuple[cryptography.hazmat.primitives.asymmetric.rsa.RsaPublicKey,
                    cryptography.hazmat.primitives.asymmetric.rsa.RsaPrivateKey]
        """
        return self.rsa_keypair()
    
    def publicKeyFromBase64(self):
        """
        Returns the public key of the RSA key pair used by the utility, encoded in base64.

        :return: The public key, encoded in base64.
        :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RsaPublicKey
        """
        # if client wants to generate a new key pair before fetching the public key, then run generateRSAKeyPair first
        return self._rsa_keypair[0]

    def privateKeyFromBase64(self):
        """
        Returns the private key of the RSA key pair used by the utility, encoded in base64.

        :return: The private key, encoded in base64.
        :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RsaPrivateKey
        """
        # if client wants to generate a new key pair before fetching the private key, then run generateRSAKeyPair first
        return self._rsa_keypair[1]
    

