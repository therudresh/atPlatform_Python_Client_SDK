import unittest

from main.api.atRootConnection import AtRootConnection
from main.api.atSecondaryConnection import AtSecondaryConnection

class AtSecondaryConnectionTest(unittest.TestCase):

    def testSecondaryConnection(self):
        print()
        rootConnection = AtRootConnection.getInstance(verbose=True)
        secondaryAddress = rootConnection.findSecondary("@27barracuda")
        secondaryAddress = secondaryAddress.split(":")
        secondaryConnection = AtSecondaryConnection(secondaryAddress[0], secondaryAddress[1], verbose=True)
        secondaryConnection.connect()
        self.assertTrue(secondaryConnection.isConnected())

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(AtSecondaryConnectionTest)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)