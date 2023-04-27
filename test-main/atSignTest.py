import unittest

from main.api.AtSign import AtSign
from main.api.keysUtil import KeysUtil

class AtSignTest(unittest.TestCase):
    keysb = None
    keyst = None

    def setUp(self):
        self.verbose = False
        return super().setUp()

    def testAtSignAuthentication(self):
        print()
        keys = KeysUtil.loadKeys("@amateur93")
        atsign = AtSign("@amateur93", verbose=self.verbose)
        authenticated = atsign.authenticate(keys)
        self.assertTrue(authenticated)
        

    def testMultipleAtSignAuthentication(self):
        print()
        universal27alooKeys = KeysUtil.loadKeys("@universal27aloo")
        universal27alooAtsign = AtSign("@universal27aloo", verbose=self.verbose)
        self.assertTrue(universal27alooAtsign.authenticate(universal27alooKeys))

        amateur93Keys = KeysUtil.loadKeys("@amateur93")
        amateur93Atsign = AtSign("@amateur93", verbose=self.verbose)
        self.assertTrue(amateur93Atsign.authenticate(amateur93Keys))

    def testAtSignLocalUpdateAndLocalLookup(self):
        print()
        keys = KeysUtil.loadKeys("@amateur93")
        atsign = AtSign("@amateur93", verbose=self.verbose)
        atsign.authenticate(keys)
        atsign.lUpdate("foo", "bar")
        response = atsign.lLookUp("foo")
        self.assertEqual("bar", response)

    def testAtSignUpdateAndLookup(self):
        print()
        universal27alooKeys = KeysUtil.loadKeys("@universal27aloo")
        universal27alooAtsign = AtSign("@universal27aloo", verbose=self.verbose)
        universal27alooAtsign.authenticate(universal27alooKeys)

        amateur93Keys = KeysUtil.loadKeys("@amateur93")
        amateur93Atsign = AtSign("@amateur93", verbose=self.verbose)
        amateur93Atsign.authenticate(amateur93Keys)

        universal27alooAtsign.update("hello", "world", "@amateur93")
        response = amateur93Atsign.lookUp("hello", "@universal27aloo")

        self.assertEqual("world", response)

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(AtSignTest)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
    
