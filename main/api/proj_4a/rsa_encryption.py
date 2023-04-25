"""
-*- coding: utf-8 -*-
Implementation of the RSA Encryption and Decryption functionality
Created: April 2023
Owners: Project 4a: Muskaan Manocha, Prem Desai, Yeshaswini Murthy
"""
    
import rsa
import base64
from cryptography.hazmat.primitives import serialization
from encryption import Encryption

class RsaEncryption(Encryption):

    def generate_key_pair(self, b=2048):
        """
        Generate a pair of public and private keys for RSA encryption.
        
        Returns:
            A tuple containing the public key and the private key.
        """
        (public_key, private_key) = rsa.newkeys(b)
        return (public_key, private_key)

    def encrypt(self, message, public_key):
        """
        Encrypt a message using RSA encryption with a public key.
        
        Args:
            message (str): The message to be encrypted.
            public_key (rsa.PublicKey): The public key to be used for encryption.
        
        Returns:
            The encrypted message as a Base64-encoded string.
        """
        encoded_message = message.encode()
        encrypted_message = rsa.encrypt(encoded_message, public_key)
        return base64.b64encode(encrypted_message).decode()

    def decrypt(self, encrypted_message, private_key):
        """
        Decrypt a message using RSA encryption with a private key.
        
        Args:
            encrypted_message (str): The encrypted message as a Base64-encoded string.
            private_key (rsa.PrivateKey): The private key to be used for decryption.
        
        Returns:
            The decrypted message as a string.
        """
        decoded_message = base64.b64decode(encrypted_message)
        decrypted_message = rsa.decrypt(decoded_message, private_key)
        return decrypted_message.decode()

    def sign(self, message, private_key, sign='SHA-256'):
        """
        Sign a message using RSA encryption with a private key.
        
        Args:
            message (str): The message to be signed.
            private_key (rsa.PrivateKey): The private key to be used for signing.
            sign (str): default rsa sign used is SHA-256
        
        Returns:
            The signature as a Base64-encoded string.
        """
        encoded_message = message.encode()
        signature = rsa.sign(encoded_message, private_key, sign)
        return base64.b64encode(signature).decode()

    def verify(self, message, signature, public_key):
        """
        Verify a message's signature using RSA encryption with a public key.
        
        Args:
            message (str): The message whose signature is to be verified.
            signature (str): The signature to be verified as a Base64-encoded string.
            public_key (rsa.PublicKey): The public key to be used for verification.
        
        Returns:
            True if the signature is valid, False otherwise.
        """
        encoded_message = message.encode()
        decoded_signature = base64.b64decode(signature)
        try:
            rsa.verify(encoded_message, decoded_signature, public_key)
            return True
        except:
            return False


# Example usage of RsaEncryption class, uncomment everything below and run this file for demo output
   
# rsa_encryption = RsaEncryption()

# (public_key, private_key) = rsa_encryption.generate_key_pair()

# message = "Hello, world!"
# encrypted_message = rsa_encryption.encrypt(message, public_key)

# decrypted_message = rsa_encryption.decrypt(encrypted_message, private_key)

# signature = rsa_encryption.sign(message, private_key)

# is_valid_signature = rsa_encryption.verify(message, signature, public_key)

# print("Public Key:", public_key)
# print("Private Key:", private_key)
# print("Original Message:", message)
# print("Encrypted Message:", encrypted_message)
# print("Decrypted Message:", decrypted_message)
# print("Signature:", signature)
# print("Is Valid Signature?", is_valid_signature)