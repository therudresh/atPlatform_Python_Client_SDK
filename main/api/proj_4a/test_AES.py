import unittest
import base64
import secrets

from aes_encryption import AesEncryption
# from proj_4a.aes_encryption import *
class TestAesEncryption(unittest.TestCase):
    def setUp(self):
        # Create an instance of the AesEncryption class with a random key
        self.key = base64.b64encode(secrets.token_bytes(32)).decode()
        self.aes = AesEncryption(self.key)

    def test_encrypt_decrypt(self):
        # Define a plaintext string to encrypt
        plaintext = "Hello, world!"

        # Encrypt the plaintext using AES in CTR mode with a 256-bit key
        ciphertext = self.aes.encrypt(plaintext.encode(), self.aes.key, self.aes.iv)

        # Decrypt the ciphertext using AES in CTR mode with a 256-bit key
        decrypted_plaintext = self.aes.decrypt(ciphertext, self.aes.key, self.aes.iv)

        # Assert that the original plaintext and the decrypted plaintext match
        self.assertEqual(plaintext.encode(), decrypted_plaintext)

    def test_encrypt_to_base64_decrypt_base64(self):
        # Define a plaintext string to encrypt
        plaintext = "Hello, world!"

        # Encrypt the plaintext using AES in CBC mode with PKCS7 padding
        encrypted_text = self.aes.encrypt_to_base64(plaintext, self.aes.key_base64)

        # Decrypt the ciphertext using AES in CBC mode with PKCS7 padding
        decrypted_text = self.aes.decrypt_base64(encrypted_text, self.aes.key_base64)

        # Assert that the original plaintext and the decrypted plaintext match
        self.assertEqual(plaintext, decrypted_text)

if __name__ == '__main__':
    unittest.main()
