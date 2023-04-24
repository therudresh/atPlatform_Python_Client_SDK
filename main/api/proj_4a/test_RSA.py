import unittest
from rsa_encryption import RsaEncryption
# from proj_4a.rsa_encryption import *

class TestRsaEncryption(unittest.TestCase):
    
    def setUp(self):
        self.rsa = RsaEncryption()
        self.public_key, self.private_key = self.rsa.generate_key_pair()
    
    def test_encrypt_decrypt(self):
        message = "Hello, World!"
        encrypted_message = self.rsa.encrypt(message, self.public_key)
        decrypted_message = self.rsa.decrypt(encrypted_message, self.private_key)
        self.assertEqual(message, decrypted_message)
    
    def test_sign_verify(self):
        message = "Hello, World!"
        signature = self.rsa.sign(message, self.private_key)
        self.assertTrue(self.rsa.verify(message, signature, self.public_key))
    
if __name__ == '__main__':
    unittest.main()
