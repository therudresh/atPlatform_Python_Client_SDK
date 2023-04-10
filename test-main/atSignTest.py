import unittest
import sys

from main.api.AtSign import AtSign
from main.api.keysUtil import KeysUtil

class AtSignTest(unittest.TestCase):
    keys = None

    def setUp(self) -> None:
        self.keys = KeysUtil.loadKeys("@27barracuda")
        return super().setUp()
    
    def testAtSignAuthentication(self):
        atsign = AtSign("@27barracuda")
        atsign.authenticate(self.keys)
        self.assertTrue(True)

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(AtSignTest)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)