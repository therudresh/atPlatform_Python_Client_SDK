import unittest

from ..main.api.atSign import AtSign

class AtSignTest(unittest.TestCase):
    
    def testAtSignAuthentication(self):
        obj = AtSign("27barracuda")
        self.assertTrue(obj.authenticate())