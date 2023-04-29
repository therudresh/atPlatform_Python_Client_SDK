"""
-*- coding: utf-8 -*-
Implementation of the Encryption Utility
Created: April 2023
Owners: Project 4a: Muskaan Manocha, Prem Desai, Yeshaswini Murthy
"""

import binascii
import secrets
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

from aes_encryption import *
from rsa_encryption import *

class EncryptionUtil(AesEncryption, RsaEncryption):

    """
    Utility Methods:
    __init__() : Initializes the nonce and RSA keypair so that we can use the properties/setters accordingly
    nonce() : Getter for the nonce
    nonce(bytes=16) : Setter for the nonce, accepts number of bytes to generate
    aes_key() : Getter for the aes key
    aes_key(bytes=32) : Setter for the aes key, accepts number of bytes to generate
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
        self._aes_key = None
        self._rsa_keypair = ()

    @property
    def nonce(self):
        """
        Returns the nonce
        """
        return self._nonce
	
    @nonce.setter
    def nonce(self, b=16):
        """
        Sets the nonce
        Parameters:
        bytes(int): number of bytes to generate, defaults to 16
        """
        self._nonce = secrets.token_bytes(b)

    @property
    def aes_key(self):
        """
        Returns the nonce
        """
        return self._aes_key
	
    @aes_key.setter
    def aes_key(self, b=32):
        """
        Sets the nonce
        Parameters:
        bytes(int): number of bytes to generate, defaults to 16
        """
        self._aes_key = secrets.token_bytes(b)

    @property
    def rsa_keypair(self):
        """
        Returns the RSA keypair
        """
        return self._rsa_keypair
	
    @rsa_keypair.setter
    def rsa_keypair(self, b=2048):
        """
        Sets the RSA keypair
        Parameters:
        bytes(int): number of bytes to generate, defaults to 2048
        """
        self._rsa_keypair = self.generate_key_pair(b)
    
    def aes_encrypt(self, clearText, keyBase64, nonce_bytes=16, from_base64=True, encoded_text=False):
        """
        Encrypts clearText using the provided keyBase64
        Parameters:
        clearText(str): The text to encrypt
        keyBase64(str): The key to used for encryption, as a base64 encoded string
        from_base64(bool): True if the key provided is base 64 encoded
        encoded_text(bool): True if the clearText provided is base 64 encoded
        """
        self.nonce = nonce_bytes
        if from_base64:
            key = EncryptionUtil.decodeAESKeyBase64(keyBase64)
        if not encoded_text:
            clearText = clearText.encode()
        return AesEncryption.encrypt(self, clearText, key, self._nonce)
        
    def aes_decrypt(self, encryptedText, selfEncryptionKey, from_base64=True):
        """
        Encrypts clearText using the provided keyBase64
        Parameters:
        encryptedText(str): The text to decrypt
        selfEncryptionKey(str): The key to use for decryption, as a base64 encoded string
        from_base64(bool): True if the key provides is base 64 encoded
        """
        if from_base64:
            key = EncryptionUtil.decodeAESKeyBase64(selfEncryptionKey)
        plaintext = AesEncryption.decrypt(self, encryptedText, key, self._nonce)
        return plaintext.decode('utf-8')
        
    @staticmethod
    def generateAESKeyBase64(b=32):
        """
        Generates a new AES key and returns it as a base64 encoded string
        """
        aes_key = secrets.token_bytes(b)
        aes_key_encoded = base64.b64encode(aes_key)
        return aes_key_encoded
    
    @staticmethod
    def decodeAESKeyBase64(base64_encoded_key):
        """
        decodes a base64 encoded key and returns its decoded version
        """
        decoded_key = base64.b64decode(base64_encoded_key)
        return decoded_key

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

    @staticmethod
    def signSHA256RSA(input_data, private_key):
        """
        Signs the input data using RSA-SHA256 signature with the given private key.

        :param input_data: The input data to be signed.
        :type input_data: str
        :param private_key: The private key to be used for signing.
        :type private_key: cryptography.hazmat.primitives.asymmetric.rsa.RsaKey
        :return: The signed data, encoded in base64.
        :rtype: str
        """
        hash_data = SHA256.new(input_data.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(hash_data)
        return base64.b64encode(signature).decode('utf-8')

    def generateRSAKeyPair(self, bytes=2048):
        """
        Generates a new RSA key pair.

        :return: The generated RSA key pair, consisting of a public key and a private key.
        :rtype: None
        """
        self.rsa_keypair = bytes
        return self.rsa_keypair
    
    def publicKeyFromBase64(self):
        """
        Returns the public key of the RSA key pair used by the utility, encoded in base64.

        :return: The public key, encoded in base64.
        :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RsaPublicKey
        """
        # if client wants to generate a new key pair before fetching the public key, then run generateRSAKeyPair first
        return self.rsa_keypair[0]

    def privateKeyFromBase64(self):
        """
        Returns the private key of the RSA key pair used by the utility, encoded in base64.

        :return: The private key, encoded in base64.
        :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RsaPrivateKey
        """
        # if client wants to generate a new key pair before fetching the private key, then run generateRSAKeyPair first
        return self.rsa_keypair[1]
        