from atConnection import AtConnection
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

	def authenticate(): ## `from` protocol
		return True

	## RT: FYI There are multiple types of look ups will require more than one lookup funtion
	def lookUp():
		return True

	def connectToAtSign(atSign):
		return True

	def update():
		return True

	def delete():
		return True


	## Good to have functions
	def stats():
		return True

	def sync():
		return True

	def notify():
		return True

	def monitor():
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
