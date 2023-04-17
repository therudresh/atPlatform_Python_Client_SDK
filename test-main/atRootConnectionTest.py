import unittest

from main.api.atRootConnection import AtRootConnection

class AtRootConnectionTest(unittest.TestCase):

    def testRootConnection(self):
        print()
        rootConnection = AtRootConnection.getInstance(verbose=True)
        rootConnection.connect()
        self.assertTrue(rootConnection.isConnected())

    def testFindSecondary(self):
        print()
        rootConnection = AtRootConnection.getInstance(verbose=True)
        secondaryAddress = rootConnection.findSecondary("@27barracuda")
        self.assertTrue(secondaryAddress)

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(AtRootConnectionTest)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)