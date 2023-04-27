import unittest

from main.api.AtSign import AtSign
from main.api.keysUtil import KeysUtil

class AtSignTest(unittest.TestCase):
    keysb = None
    keyst = None

    def setUp(self):
        self.keysb = KeysUtil.loadKeys("27barracuda")
        self.keyst = KeysUtil.loadKeys("19total67")
        return super().setUp()

    # def testAtSignAuthentication(self):
    #     print()
    #     atsign = AtSign("@27barracuda", verbose=True)
    #     atsign.authenticate(self.keys)
    #     atsign.lupdate("foo", "bar")
    #     response = atsign.llookUp("foo")
    #     self.assertTrue(response == "bar")

    def testAtSignAuthentication(self):
        print()
        atsignB = AtSign("@27barracuda", verbose=True)
        atsignT = AtSign("@19total67", verbose=True)

        atsignB.authenticate(self.keysb)
        atsignT.authenticate(self.keyst)

        atsignB.sUpdate(self.keysb, "foo", "bar", "19total67")
        response = atsignT.slookUp(self.keyst, "foo", "27barracuda")

        self.assertTrue(response == "bar")

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(AtSignTest)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
    