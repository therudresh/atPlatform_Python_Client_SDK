import unittest

from main.api.atRootConnection import AtRootConnection
from main.api.atSecondaryConnection import AtSecondaryConnection

class AtSecondaryConnectionTest(unittest.TestCase):

    def testSecondaryConnection(self):
        """Test secondary connection establishment."""
        print()
        rootConnection = AtRootConnection.getInstance(verbose=True)
        secondaryAddress = rootConnection.findSecondary("@27barracuda")
        secondaryAddress = secondaryAddress.split(":")
        secondaryConnection = AtSecondaryConnection(secondaryAddress[0], secondaryAddress[1], verbose=True)
        secondaryConnection.connect()
        self.assertTrue(secondaryConnection.isConnected())

    def testSecondaryConnectionFailure(self):
        """Test secondary connection failure."""
        print()
        try:
            rootConnection = AtRootConnection.getInstance(verbose=True)
            secondaryAddress = rootConnection.findSecondary("@27barracuda")
            secondaryAddress = secondaryAddress.split(":")
            secondaryConnection = AtSecondaryConnection(secondaryAddress[0]+"0", secondaryAddress[1], verbose=True)
            secondaryConnection.connect()
        except Exception as e:
            self.assertEqual("[Errno 8] nodename nor servname provided, or not known", str(e))

    def testMultipleSecondaryConnections(self):
        """Test multiple secondary connections."""
        print()
        rootConnection = AtRootConnection.getInstance(verbose=True)
        secondaryAddress1 = rootConnection.findSecondary("@27barracuda").split(":")
        secondaryConnection1 = AtSecondaryConnection(secondaryAddress1[0], secondaryAddress1[1], verbose=True)
        secondaryConnection1.connect()
        secondaryAddress2 = rootConnection.findSecondary("@19total67").split(":")
        secondaryConnection2 = AtSecondaryConnection(secondaryAddress2[0], secondaryAddress2[1], verbose=True)
        secondaryConnection1.connect()
        secondaryAddress3 = rootConnection.findSecondary("@wildgreen").split(":")
        secondaryConnection3 = AtSecondaryConnection(secondaryAddress3[0], secondaryAddress3[1], verbose=True)
        secondaryConnection3.connect()
        secondaryAddress4 = rootConnection.findSecondary("@colin").split(":")
        secondaryConnection4 = AtSecondaryConnection(secondaryAddress4[0], secondaryAddress4[1], verbose=True)
        secondaryConnection4.connect()
        
        self.assertIsNotNone(secondaryConnection1)
        self.assertIsNotNone(secondaryConnection2)
        self.assertIsNotNone(secondaryConnection3)
        self.assertIsNotNone(secondaryConnection4)

if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(AtSecondaryConnectionTest)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
