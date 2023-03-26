import time
import usocket as socket
import sys
import ssl

class AtConnection:
	url = ""
	host = ""
	port = -1

	socket = None

	def isConnected():
		return False

	def connect():
		return False

	def disconnect():
		return False

	def __init__(self, host, port):
		self.host = host
		self.port = port