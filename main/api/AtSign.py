import ssl, time

from .atConnection import AtConnection
from .EncryptionUtil import EncryptionUtil
from .keysUtil import KeysUtil


class AtSign:
	atSign = ""
	
	rootHostname = 'root.atsign.org'
	rootPort = 64
	rootAtConnection = AtConnection(rootHostname, rootPort, ssl.create_default_context())
	
	secondaryAtConnection = None

	def authenticate(self, keys): ## `from` protocol
		privateKey = signature = None
		self.secondaryAtConnection.write(f"from:{self.atSign}")
		fromResponse = self.secondaryAtConnection.read().replace('\n', '').strip()

		dataPrefix = "data:"
		if not fromResponse.startswith(dataPrefix):
			raise Exception(f"Invalid response to 'from' command: {repr(fromResponse)}")
		
		fromResponse = fromResponse[len(dataPrefix):-1]

		try:
			privateKey = EncryptionUtil.privateKeyFromBase64(keys[KeysUtil.pkamPrivateKeyName])
		except:
			raise Exception("Failed to get private key from stored string")
		
		try:
			signature = EncryptionUtil.signSHA256RSA(fromResponse, privateKey)
		except:
			raise Exception("Failed to create SHA256 signature")
		
		self.secondaryAtConnection.write(f"pkam:{signature}")
		pkamResponse = self.secondaryAtConnection.read()

		if not pkamResponse.startswith("data:success"):
			raise Exception(f"PKAM command failed: {repr(pkamResponse)}")
		
		print("Authentication Successful")

	## RT: FYI There are multiple types of look ups will require more than one lookup funtion
	def LookUp(self, key : str, location : str):
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation

		self.secondaryAtConnection.write(f"lookup:{key}{uLocation}")
		lookupResponse = self.secondaryAtConnection.read().replace('\n', '').strip()[:-1]

		return lookupResponse

	def llookUp(self, key : str):
		self.secondaryAtConnection.write(f"llookup:{key}{self.atSign}")

		prefix = "data:"
		lookupResponse = self.secondaryAtConnection.read().replace('\n', '').strip()

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
		self.secondaryAtConnection.write(f"update:{uLocation}:{key}{self.atSign} {value}")
		updateResponse = self.secondaryAtConnection.read().replace('\n', '').strip()

		if("data:" in updateResponse):
			return True
		else:
			print(f"Update Failed: {updateResponse}")
			return False


	def lupdate(self, key : str, value : str):
		self.secondaryAtConnection.write(f"update:{key}{self.atSign} {value}")
		updateResponse = self.secondaryAtConnection.read().replace('\n', '').strip()

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

	def __init__(self, atSign : str):
		if(atSign[0] == '@'):
			self.atSign = atSign
		else:
			self.atSign = "@" + atSign
		self.rootAtConnection.connect()
		self.rootAtConnection.write(atSign[1:])

		confirmationResponse =	self.rootAtConnection.read().replace('\r\n', '')

		if confirmationResponse == "@":
			print("Root connection successful")
		else:
			raise Exception("Root connection failed!!!")
		
		self.rootAtConnection.write(atSign[1:])
		time.sleep(2)

		#### Make this less error pruned :)
		secondaryAtResponse =	self.rootAtConnection.read().replace('\r\n', '').replace('@','').split(':')
		
		secondaryHostname = secondaryAtResponse[0]
		secondaryPort = secondaryAtResponse[1]
		self.secondaryAtConnection = AtConnection(secondaryHostname, secondaryPort, ssl.create_default_context())
		self.secondaryAtConnection.connect()
		confirmationResponse =	self.secondaryAtConnection.read().replace('\r\n', '')
		if confirmationResponse == "@":
			print("Secondary server connection successful")
		else:
			raise Exception("Secondary server connection failed!!!")