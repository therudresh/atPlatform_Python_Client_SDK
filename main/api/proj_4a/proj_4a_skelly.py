import base64, binascii
import secrets
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import base64
import secrets
import proj_4a_AES
import proj_4a_RSA

class EncryptionUtil():
    iv = b'\x00'*16
    nonce = secrets.token_bytes(16)


    @staticmethod
    def aesDecryptFromBase64(clearText, keyBase64):
        nonce = secrets.token_bytes(16)
        return proj_4a_AES.aes_ctr_256_encrypt(clearText, keyBase64, nonce)
        

    @staticmethod
    def aesDecryptFromBase64(encryptedText, selfEncryptionKey):
        ciphertext = binascii.a2b_base64(encryptedText)
        key = binascii.a2b_base64(selfEncryptionKey)
        cipher = Cipher(algorithms.AES(key), modes.CTR(EncryptionUtil.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Unpad the plaintext using PKCS7 padding
        padder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = padder.update(plaintext) + padder.finalize()

        # Print the decrypted plaintext
        return plaintext.decode('utf-8')
    
    @staticmethod
    def generateRSAKeyPair():
        return proj_4a_RSA.RSA_2048__key_generation()
        

    @staticmethod
    def generateAESKeyBase64():
        aes_key = secrets.token_bytes(32)
        aes_key_encoded=base64.b64encode(aes_key)
        return aes_key_encoded
        

    @staticmethod
    def rsaDecryptFromBase64(cipherText, privateKeyBase64):
        return proj_4a_RSA.RSA_2048_decryption(cipherText, privateKeyBase64)
        

    @staticmethod
    def rsaEncryptToBase64(clearText, publicKeyBase64):
        return proj_4a_RSA.RSA_2048_encryption(clearText, publicKeyBase64)

    @staticmethod
    def signSHA256RSA(input_data, private_key):
        hash_data = SHA256.new(input_data.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(hash_data)
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def publicKeyFromBase64(s):
        rsa_keys=proj_4a_RSA.RSA_2048__key_generation()
        return rsa_keys[0]


    @staticmethod
    def privateKeyFromBase64(s):
        rsa_keys=proj_4a_RSA.RSA_2048__key_generation()
        return rsa_keys[1]
    


    

    