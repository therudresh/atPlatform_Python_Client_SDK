from .atConnection import AtConnection
from . import EncryptionUtil
from .keysUtil import KeysUtil
import ssl
import socket
import time
import sys

class AtSign:
	atSign = ""
	
	rootHostname = 'root.atsign.org'
	rootPort = 64
	rootAtConnection = AtConnection(rootHostname, rootPort, ssl.create_default_context())
	
	secondaryAtConnection = None

	def authenticate(self, keys): ## `from` protocol
		print(self.secondaryAtConnection)
		self.secondaryAtConnection.write(f"from:{self.atSign}\n")
		# time.sleep(2)
		self.secondaryAtConnection.read()
		fromResponse = self.secondaryAtConnection.read()
		# self.secondaryAtConnection.write(f"from:@27barracuda\n")
		# time.sleep(15)
		# fromResponse = self.secondaryAtConnection.read()
		# print("from response : ", fromResponse)

		dataPrefix = "data:"
		if not fromResponse.startswith(dataPrefix):
			raise Exception(f"Invalid response to 'from' command: {fromResponse}")
		
		fromResponse = fromResponse[len(dataPrefix):]

		privateKey = None
		try:
			privateKey = EncryptionUtil.privateKeyFromBase64(keys[KeysUtil.pkamPrivateKeyName])
		except:
			raise Exception("Failed to get private key from stored string")
		
		signature = None
		try:
			signature = EncryptionUtil.signSHA256RSA(fromResponse, privateKey)
		except:
			raise Exception("Failed to create SHA256 signature")
		
		self.secondaryAtConnection.write(f"pkam:{signature}")
		# time.sleep(2)
		pkamResponse = self.secondaryAtConnection.read()

		print("XXXXXXXX", pkamResponse)

		EncryptionUtil.verify(keys[KeysUtil.pkamPublicKeyName], signature, fromResponse)
		input()
		if not pkamResponse.startswith("data:success"):
			raise Exception(f"PKAM command failed: {pkamResponse}")

	## RT: FYI There are multiple types of look ups will require more than one lookup funtion
	def lookUp(self):
		return True

	def connectToAtSign(atSign):
		return True

	def update(self):
		return True

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
		print("((((()))))", confirmationResponse)
		self.rootAtConnection.write(atSign[1:])
		time.sleep(2)

		#### Make this less error pruned :)
		secondaryAtResponse =	self.rootAtConnection.read().replace('\r\n', '').replace('@','').split(':')
		print("$$$$$$", secondaryAtResponse)
		secondaryHostname = secondaryAtResponse[0]
		secondaryPort = secondaryAtResponse[1]
		self.secondaryAtConnection = AtConnection(secondaryHostname, secondaryPort, ssl.create_default_context())
		self.secondaryAtConnection.connect()


if __name__ == "__main__":
	keys = KeysUtil.loadKeys("27barracuda")

	atsign = AtSign("@wildgreen")
	atsign.authenticate()