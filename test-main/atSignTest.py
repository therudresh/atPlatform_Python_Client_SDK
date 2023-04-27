import unittest

from main.api.AtSign import AtSign
from main.api.keysUtil import KeysUtil

class AtSignTest(unittest.TestCase):
    keys = None

    def setUp(self):
        self.keys = KeysUtil.loadKeys("27barracuda")
        return super().setUp()
    
    def testAtSignAuthentication(self):
        print()
        atsign = AtSign("@27barracuda", verbose=True)
        atsign.authenticate(self.keys)
        atsign.lupdate("foo", "bar")
        response = atsign.llookUp("foo")
        self.assertTrue(response == "bar")

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(AtSignTest)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
    