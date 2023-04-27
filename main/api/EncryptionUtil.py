import base64, binascii, os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_v1_5

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class EncryptionUtil():
    iv = b'\x00'*16
    
    @staticmethod
    def aesEncryptFromBase64(clearText, keyBase64):
        clearText64 = clearText
        key = binascii.a2b_base64(keyBase64)
        cipher = Cipher(algorithms.AES(key), modes.CTR(EncryptionUtil.iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        paddedPlaintext = padder.update(clearText64) + padder.finalize()
        cipherText = encryptor.update(paddedPlaintext) + encryptor.finalize()
        return base64.b64encode(cipherText).decode()

    @staticmethod
    def aesDecryptFromBase64(encryptedText, selfEncryptionKey):
        cipherText = binascii.a2b_base64(encryptedText)
        key = binascii.a2b_base64(selfEncryptionKey)
        cipher = Cipher(algorithms.AES(key), modes.CTR(EncryptionUtil.iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plainText = decryptor.update(cipherText) + decryptor.finalize()

        # Unpad the plainText using PKCS7 padding
        padder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plainText = padder.update(plainText) + padder.finalize()

        # Print the decrypted plaintext
        return plainText.decode('utf-8')
    
    @staticmethod
    def generateRSAKeyPair():
        return RSA.generate(2048)

    @staticmethod
    def generateAESKeyBase64():
        return base64.b64encode(os.urandom(32)).decode("utf-8")

    @staticmethod
    def rsaDecryptFromBase64(cipherText, privateKeyBase64):
        privateKey = EncryptionUtil.RSAKeyFromBase64(privateKeyBase64)
        cipher = PKCS1_v1_5.new(privateKey)
        decoded = base64.b64decode(cipherText)
        decryptedBytes = cipher.decrypt(decoded, None)
        return decryptedBytes.decode('utf-8')

    @staticmethod
    def rsaEncryptToBase64(clearText, publicKeyBase64):
        publicKey = EncryptionUtil.RSAKeyFromBase64(publicKeyBase64)
        cipher = PKCS1_v1_5.new(publicKey)
        clearTextBytes = clearText.encode('utf-8')
        encryptedBytes = cipher.encrypt(clearTextBytes)
        return base64.b64encode(encryptedBytes).decode('utf-8')

    @staticmethod
    def signSHA256RSA(inputData, privateKey):
        hashData = SHA256.new(inputData.encode('utf-8'))
        signature = pkcs1_15.new(privateKey).sign(hashData)
        return base64.b64encode(signature).decode('utf-8')
    
    @staticmethod
    def RSAKeyFromBase64(s):
        keyBytes = base64.b64decode(s.encode('utf-8'))
        return RSA.import_key(keyBytes)