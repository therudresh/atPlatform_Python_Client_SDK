import socket

from abc import ABC, abstractmethod

class AtConnection(ABC):
	url = ""
	host = ""
	port = -1
	connected = False

	addrInfo = None
	context = None
	_socket = None

	def write(self, data : str):
		## implement multi send / a loop to send larger data size
		self.secureRootSocket.write(data.encode())

	def read(self):
		## Make return type a bit more typed and try to remove 2048 size cap (make it streamy)
		response = b''
		data = self.secureRootSocket.read(2048)
		response += data
		return response.decode()


	def isConnected(self):
		return self.connected

	def connect(self):
		if not self.connected:
			try:
				self._socket.connect(self.addrInfo)
				self.secureRootSocket = self.context.wrap_socket(self._socket, server_hostname=self.host, do_handshake_on_connect = True)
			except OSError as e:
				if str(e) == '119':
					print("In Progress")
				else:
					raise e
			self.connected = True
			self.read()

	def disconnect(self):
		self.secureRootSocket.close()
		self.connected = False

	@abstractmethod
	def parseRawResponse(self, rawResponse):
		pass

	def executeCommand(self, command, retryOnException=0, readTheResponse=True):
		try:
			if not command.endswith("\n"):
				command += "\n"
			self.write(command)

			if self.verbose:
				print(f"\tSENT: {repr(command.strip())}")

			if readTheResponse:
				# Responses are always terminated by newline
				rawResponse = self.read()
				if self.verbose:
					print(f"\tRCVD: {repr(rawResponse)}")

				return self.parseRawResponse(rawResponse)
			else:
				return ""
		except Exception as first:
			self.disconnect()

			if retryOnException:
				print(f"\tCaught exception {str(first)} : reconnecting")
				try:
					self.connect()
					return self.executeCommand(command, False, True)
				except Exception as second:
					import traceback
					traceback.print_exc()
					raise Exception(f"Failed to reconnect after original exception {str(first)} : ", second)
			else:
				self.connected = False
				raise Exception(str(first))

	def __str__(self):
		return f"{self.host}:{self.port}"

	def __init__(self, host, port, context, verbose=False):
		self.host = host
		self.port = port
		self.context = context
		self.addrInfo = socket.getaddrinfo(host, port)[0][-1]
		self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		self.secureRootSocket = None
		self.verbose = verbose

		