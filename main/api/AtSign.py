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
		
		return True

	def lookUp(self, key : str, location : str):
		prefix = "data:"
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation

		lookupResponse = self.secondaryConnection.executeCommand(f"lookup:{key}{uLocation}")
		
		if(not lookupResponse.startswith(prefix)):
			print("llookup failed")
		else:
			lookupResponse = lookupResponse[len(prefix):-(len(self.atSign) + 1)]

		if(not lookupResponse.startswith(prefix)):
			print("lookup failed")
		else:
			lookupResponse = lookupResponse[len(prefix):-(len(self.atSign) + 1)]

		return lookupResponse

	def plookUp(self, key : str, location : str):
		prefix = "data:"
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation

		lookupResponse = self.secondaryConnection.executeCommand(f"plookup:{key}{uLocation}")

		if(not lookupResponse.startswith(prefix)):
			print("plookup failed")
		else:
			lookupResponse = lookupResponse[len(prefix):-(len(self.atSign) + 1)]

		return lookupResponse

	def lLookUp(self, key : str):
		prefix = "data:"
		lookupResponse = self.secondaryConnection.executeCommand(f"llookup:{key}{self.atSign}")

		if(not lookupResponse.startswith(prefix)):
			print("llookup failed")
		else:
			lookupResponse = lookupResponse[len(prefix):-(len(self.atSign) + 1)]

		return lookupResponse

	def slookUp(self, keys, key : str, location : str):
		prefix = "error:"
		uLocation = location
		
		if(location[0] == '@'):
			uLocation = uLocation[1:]

		lookupResponse = self.lookUp("shared_key", uLocation)

		if(lookupResponse.startswith(prefix)):
			return "ERROR: No sharedkeys to decrypt"
		else:
			sharedAESKey = EncryptionUtil.rsaDecryptFromBase64(lookupResponse, keys[KeysUtil.encryptionPrivateKeyName])

			lookupValueResponse = self.lookUp(key, uLocation)

			if(not lookupValueResponse.startswith(prefix)):
				decrypeddValue = EncryptionUtil.aesDecryptFromBase64(lookupValueResponse, sharedAESKey)
				return decrypeddValue;
			else:
				return "ERROR: No key found"

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

	def publicKeyUpdate(self, keyShare, location : str, time : str):
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation
		updateResponse = self.secondaryConnection.executeCommand(f"update:ttr:{time}:{uLocation}:publickey{self.atSign} {keyShare}")

		if("data:" in updateResponse):
			return True
		else:
			print(f"Update Failed: {updateResponse}")
			return False

	def sharedKeyUpdate(self, keyShare, location : str, time : str):
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation
		updateResponse = self.secondaryConnection.executeCommand(f"update:ttr:{time}:{uLocation}:shared_key{self.atSign} {keyShare}")

		if("data:" in updateResponse):
			return True
		else:
			print(f"Update Failed: {updateResponse}")
			return False

	def sUpdate(self, keys, key : str, value : str, location : str):
		prefix = "error:"
		uLocation = location
		
		if(location[0] == '@'):
			uLocation = uLocation[1:]

		lookupResponse = self.llookUp("shared_key." + uLocation)

		sharedAESKey = EncryptionUtil.generateAESKeyBase64()

		if(not lookupResponse.startswith(prefix)):
			sharedAESKey = EncryptionUtil.rsaDecryptFromBase64(lookupResponse, keys[KeysUtil.pkamPrivateKeyName])
		else:
			lookupPKResponse = self.plookUp("publickey", uLocation)
			if(not lookupPKResponse.startswith(prefix)):
				encryptedSharedAESKey = EncryptionUtil.rsaEncryptToBase64(sharedAESKey, lookupPKResponse)
				self.sharedKeyUpdate(encryptedSharedAESKey, location, "86400")
			else:
				return False

		encryptedValue = EncryptionUtil.aesEncryptFromBase64(value.encode('utf-8'), sharedAESKey)

		updateResponse = self.secondaryConnection.executeCommand(f"update:@{uLocation}:{key}{self.atSign} {encryptedValue}")

		if("data:" in updateResponse):
			return True
		else:
			print(f"Update Failed: {updateResponse}")
			return False

		return True

	def lUpdate(self, key : str, value : str):
		updateResponse = self.secondaryConnection.executeCommand(f"update:{key}{self.atSign} {value}")

		if("data:" in updateResponse):
			return True
		else:
			print(f"Self Update Failed: {updateResponse}")
			return False
		

	def delete(self, key : str):
		delResponse = self.secondaryConnection.executeCommand(f"delete:{key}{self.atSign}")

		if("data:" in delResponse):
			return True
		else:
			print(f"Self delete Failed: {delResponse}")
			return False


	## Good to have functions
	# def stats(self):
	# 	return True

	# def sync(self):
	# 	return True

	# def notify(self):
	# 	return True

	# def monitor(self):
	# 	return True

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
