import ssl, time

from .atRootConnection import AtRootConnection
from .atSecondaryConnection import AtSecondaryConnection
from .EncryptionUtil import EncryptionUtil
from .keysUtil import KeysUtil


class AtSign:

	def authenticate(self, keys): ## `from` protocol
		privateKey = signature = None
		fromResponse = self.secondaryConnection.executeCommand(f"from:{self.atSign}")
	
		dataPrefix = "data:"
		if not fromResponse.startswith(dataPrefix):
			raise Exception(f"Invalid response to 'from' command: {repr(fromResponse)}")
		
		fromResponse = fromResponse[len(dataPrefix):]

		try:
			privateKey = EncryptionUtil.RSAKeyFromBase64(keys[KeysUtil.pkamPrivateKeyName])
		except:
			raise Exception("Failed to get private key from stored string")
		
		try:
			signature = EncryptionUtil.signSHA256RSA(fromResponse, privateKey)
		except:
			raise Exception("Failed to create SHA256 signature")
		
		pkamResponse = self.secondaryConnection.executeCommand(f"pkam:{signature}")

		if not pkamResponse.startswith("data:success"):
			raise Exception(f"PKAM command failed: {repr(pkamResponse)}")
		
		if self.verbose:
			print("Authentication Successful")

	## RT: FYI There are multiple types of look ups will require more than one lookup funtion
	def LookUp(self, key : str, location : str):
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation

		lookupResponse = self.secondaryConnection.executeCommand(f"lookup:{key}{uLocation}")

		return lookupResponse

	def llookUp(self, key : str):
		prefix = "data:"
		lookupResponse = self.secondaryConnection.executeCommand(f"llookup:{key}{self.atSign}")

		if(not lookupResponse.startswith(prefix)):
			print("llookup failed")
		else:
			lookupResponse = lookupResponse[len(prefix):-(len(self.atSign) + 1)]

		return lookupResponse

	def connectToAtSign(atSign):
		return True

	def update(self, key : str, value : str, location : str):
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation
		updateResponse = self.secondaryConnection.executeCommand(f"update:{uLocation}:{key}{self.atSign} {value}")

		if("data:" in updateResponse):
			return True
		else:
			print(f"Update Failed: {updateResponse}")
			return False


	def lupdate(self, key : str, value : str):
		updateResponse = self.secondaryConnection.executeCommand(f"update:{key}{self.atSign} {value}")

		if("data:" in updateResponse):
			return True
		else:
			print(f"Self Update Failed: {updateResponse}")
			return False
		

	def delete(self):
		return True


	## Good to have functions
	def stats(self):
		return True

	def sync(self):
		return True

	def notify(self):
		return True

	def monitor(self):
		return True

	def __init__(self, atSign, verbose=False):
		if(atSign[0] == '@'):
			self.atSign = atSign
		else:
			self.atSign = "@" + atSign
		self.verbose = verbose
		self.rootConnection = AtRootConnection.getInstance(verbose=verbose)
		
		#### Make this less error pruned :)
		secondaryAddress = self.rootConnection.findSecondary(atSign).split(":")
		
		self.secondaryConnection = AtSecondaryConnection(host=secondaryAddress[0], port=secondaryAddress[1], verbose=verbose)
		self.secondaryConnection.connect()