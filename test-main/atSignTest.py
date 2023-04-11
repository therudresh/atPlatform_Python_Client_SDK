import unittest

from main.api.AtSign import AtSign
from main.api.keysUtil import KeysUtil

class AtSignTest(unittest.TestCase):
    keys = None

    def setUp(self) -> None:
        self.keys = KeysUtil.loadKeys("@19total67")
        return super().setUp()
    
    def testAtSignAuthentication(self):
        print()
        atsign = AtSign("@19total67")
        atsign.authenticate(self.keys)
        atsign.lupdate("foo", "bar")
        response = atsign.llookUp("foo")
        self.assertTrue(response == "bar")

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(AtSignTest)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
    