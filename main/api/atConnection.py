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

	def write(data : str):
		## implement multi send / a loop to send larger data size
		modData = data
		if(data.endswith('\n')):
			modData += "\n" 
		secureRootSocket = context.wrap_socket(_socket, server_hostname=host, do_handshake_on_connect = True)
		secureRootSocket.write((modData).encode())

	def read():
		## Make return type a bit more typed and try to remove 2048 size cap (make it streamy)
		response = b''
		data = secureRootSocket.read(2048)
		response += data
		return response.decode()


	def isConnected():
		return connected

	def connect():
		try:
			_socket.connect(addrInfo)
		except OSError as e:
			if str(e) == '119':
				print("In Progress")
			else:
				raise e
		connected = True

	def disconnect():
		secureRootSocket.close()
		connected = False

	def __init__(self, host, port, context):
		self.host = host
		self.port = port
		self.context = context
		self.addrInfo = socket.getaddrinfo(host, port)[0][-1]
		self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

		