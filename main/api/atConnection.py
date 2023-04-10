import time
import socket
import sys
import ssl

class AtConnection:
	url = ""
	host = ""
	port = -1
	connected = False

	addrInfo = None
	context = None
	_socket = None

	def write(self, data : str):
		## implement multi send / a loop to send larger data size
		modData = data
		
		if(not data.endswith("\n")):
			modData += "\n" 
			print("HERE!!!!")

		print("\n\n@@@@", modData)
		print("%%%%%%%%", self.secureRootSocket)
		self.secureRootSocket.write(modData.encode())

	def read(self):
		## Make return type a bit more typed and try to remove 2048 size cap (make it streamy)
		response = b''
		data = self.secureRootSocket.read(2048)
		response += data
		return response.decode()


	def isConnected(self):
		return self.connected

	def connect(self):
		try:
			self._socket.connect(self.addrInfo)
			self.secureRootSocket = self.context.wrap_socket(self._socket, server_hostname=self.host, do_handshake_on_connect = True)
		except OSError as e:
			if str(e) == '119':
				print("In Progress")
			else:
				raise e
		self.connected = True

	def disconnect(self):
		self.secureRootSocket.close()
		self.connected = False

	def __str__(self):
		return f"{self.host}:{self.port}"

	def __init__(self, host, port, context):
		self.host = host
		self.port = port
		self.context = context
		self.addrInfo = socket.getaddrinfo(host, port)[0][-1]
		self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		self.secureRootSocket = None

		