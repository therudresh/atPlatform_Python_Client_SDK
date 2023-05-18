import unittest

from main.api.atRootConnection import AtRootConnection

class AtRootConnectionTest(unittest.TestCase):

    def testRootConnection(self):
        """Test root connection establishment."""
        print()
        rootConnection = AtRootConnection.getInstance(verbose=True)
        rootConnection.connect()
        self.assertTrue(rootConnection.isConnected())

    def testFindSecondary(self):
        """Test finding a secondary server address."""
        print()
        rootConnection = AtRootConnection.getInstance(verbose=True)
        secondaryAddress = rootConnection.findSecondary("@27barracuda")
        self.assertIsNotNone(secondaryAddress)

    def testFindSecondaryFailure(self):
        """Test finding a secondary server address for a non-existent AtSign."""
        print()
        try:
            rootConnection = AtRootConnection.getInstance(verbose=True)
            secondaryAddress = rootConnection.findSecondary("@wrongAtSign")
        except Exception as e:
            self.assertEqual("Root lookup returned null for @wrongAtSign", str(e))

    def testFindMultipleSecondaryAddresses(self):
        """Test finding multiple secondary server addresses."""
        print()
        rootConnection = AtRootConnection.getInstance(verbose=True)
        secondaryAddress1 = rootConnection.findSecondary("@27barracuda").split(":")
        secondaryAddress2 = rootConnection.findSecondary("@19total67").split(":")
        secondaryAddress3 = rootConnection.findSecondary("@wildgreen").split(":")
        secondaryAddress4 = rootConnection.findSecondary("@colin").split(":")
        
        self.assertIsNotNone(secondaryAddress1)
        self.assertIsNotNone(secondaryAddress2)
        self.assertIsNotNone(secondaryAddress3)
        self.assertIsNotNone(secondaryAddress4)


if __name__ == '__main__':
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(AtRootConnectionTest)

    runner = unittest.TextTestRunner(verbosity=2)
    runner.run(suite)
