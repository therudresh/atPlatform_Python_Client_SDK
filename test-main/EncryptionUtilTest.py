import unittest, base64

from main.api.keysUtil import KeysUtil
from main.api.EncryptionUtil import EncryptionUtil

class EncryptionUtilTest(unittest.TestCase):
    def setUp(self):
        self.keys = KeysUtil.loadKeys("@27barracuda")
        return super().setUp()
    
    def testAESEncryptionDecryption(self):
        print()
        plainText = b"abcd"
        encryptedText = EncryptionUtil.aesEncryptFromBase64(plainText, self.keys[KeysUtil.selfEncryptionKeyName])
        decryptedText = EncryptionUtil.aesDecryptFromBase64(encryptedText, self.keys[KeysUtil.selfEncryptionKeyName])
        self.assertEqual(plainText.decode("utf-8"), decryptedText)

    def testRSAEncryptionDecryption(self):
        print()
        plainText = "abcd"
        encryptedText = EncryptionUtil.rsaEncryptToBase64(plainText, self.keys[KeysUtil.pkamPublicKeyName])
        decryptedText = EncryptionUtil.rsaDecryptFromBase64(encryptedText, self.keys[KeysUtil.pkamPrivateKeyName])
        self.assertEqual(plainText, decryptedText)

    def testGenerateAESKey(self):
        print()
        secretKey = EncryptionUtil.generateAESKeyBase64()
        plainText = b"XYZ"
        encryptedText = EncryptionUtil.aesEncryptFromBase64(plainText, secretKey)
        decryptedText = EncryptionUtil.aesDecryptFromBase64(encryptedText, secretKey)
        self.assertEqual(plainText.decode("utf-8"), decryptedText)
    
    def testGenerateRSAKeys(self):
        print()
        keyPair = EncryptionUtil.generateRSAKeyPair()
        plainText = "RSA"
        encryptedText = EncryptionUtil.rsaEncryptToBase64(plainText, base64.b64encode(keyPair.publickey().export_key()).decode("utf-8"))
        decryptedText = EncryptionUtil.rsaDecryptFromBase64(encryptedText, base64.b64encode(keyPair.export_key()).decode("utf-8"))
        self.assertEqual(plainText, decryptedText)

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(EncryptionUtilTest)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
    