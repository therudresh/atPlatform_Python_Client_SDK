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
		fromResponse = secondaryAtConnection.write(f"from:{self.atSign}")

		data_prefix = "data:"
		if not from_response.startswith(data_prefix):
			raise Exception(f"Invalid response to 'from' command: {from_response}")
		
		from_response = from_response[len(data_prefix):]

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
		
		pkamResponse = secondaryAtConnection.write(f"pkam:{signature}")

		print(pkamResponse)

		if not pkamResponse.startsWith("data:success"):
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
		rootAtConnection.connect()
		rootAtConnection.write(atSign[1:].encode())

		confirmationResponse = rootAtConnection.read().replace('\r\n', '')
		rootAtConnection.write((confirmationResponse + atSign[1:] + "\n").encode())

		#### Make this less error pruned :)
		secondaryAtResponse = rootAtConnection.read().replace('\r\n', '').split(':')
		secondaryHostname = secondaryAtResponse[0]
		secondaryPort = secondaryAtResponse[1]
		secondaryAtConnection = AtConnection(rootHostname, rootPort, ssl.create_default_context())


if __name__ == "__main__":
	keys = KeysUtil.loadKeys("27barracuda")

	atsign = AtSign("@wildgreen")
	atsign.authenticate()