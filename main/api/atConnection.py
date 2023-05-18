import socket

from abc import ABC, abstractmethod

  
class AtConnection(ABC):
       """
    Abstract base class for connecting to and communicating with an @ protocol server.

    ...

    Attributes
    ----------
    url : str
        the URL of the server
    host : str
        the host name or IP address of the server
    port : int
        the port number of the server
    connected : bool
        indicates if the connection is established
    addrInfo : tuple
        the address information of the server
    context : ssl.SSLContext
        the SSL context for secure connections
    _socket : socket.socket
        the socket object for the connection
    secureRootSocket : ssl.SSLSocket
        the secure socket object for the connection
    verbose : bool
        indicates if verbose output is enabled

    Methods
    -------
    write(data: str)
        Write data to the socket.
    read()
        Read data from the socket.
    isConnected()
        Check if the connection is established.
    connect()
        Establish a connection to the server.
    disconnect()
        Close the connection.
    parseRawResponse(rawResponse)
        Parse the raw response from the server.
    executeCommand(command, retryOnException=0, readTheResponse=True)
        Execute a command and retrieve the response from the server.
    """
	url = ""
	host = ""
	port = -1
	connected = False

	addrInfo = None
	context = None
	_socket = None

	 
	def write(self, data : str):
		 """
        Write data to the socket.

        Parameters
        ----------
        data : str
            The data to be written to the socket.
        """
		## implement multi send / a loop to send larger data size
		self.secureRootSocket.write(data.encode())

		  
	def read(self):
		"""
        Read data from the socket.

        Returns
        -------
        str
            The data read from the socket.
        """
		## Make return type a bit more typed and try to remove 2048 size cap (make it streamy)
		response = b''
		data = self.secureRootSocket.read(2048)
		response += data
		return response.decode()


	  
	def isConnected(self):
		"""
        Check if the connection is established.

        Returns
        -------
        bool
            True if the connection is established, False otherwise.
        """
		return self.connected

	def connect(self):
		"""Establish a connection to the server."""
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
		"""Close the connection."""
		self.secureRootSocket.close()
		self.connected = False

		   
	@abstractmethod
	def parseRawResponse(self, rawResponse):
		 """
        Parse the raw response from the server.

        Parameters
        ----------
        rawResponse : str
            The raw response received from the server.
        """
		pass

	  
	def executeCommand(self, command, retryOnException=0, readTheResponse=True):
		"""
        Execute a command and retrieve the response from the server.

        Parameters
        ----------
        command : str
            The command to be executed.
        retryOnException : int, optional
            The number of times to retry the command if an exception occurs (default is 0).
        readTheResponse : bool, optional
            Indicates if the response should be read from the server (default is True).

        Returns
        -------
        str
            The response from the server.
        """
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
			# self.disconnect()

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
		 """
        Return a string representation of the AtConnection object.

        Returns
        -------
        str
            A string representation of the AtConnection object in the format "host:port".
        """
		return f"{self.host}:{self.port}"

		   
	def __init__(self, host, port, context, verbose=False):
		 """
        Initialize the AtConnection object.

        Parameters
        ----------
        host : str
            The host name or IP address of the server.
        port : int
            The port number of the server.
        context : ssl.SSLContext
            The SSL context for secure connections.
        verbose : bool, optional
            Indicates if verbose output is enabled (default is False).
        """
		self.host = host
		self.port = port
		self.context = context
		self.addrInfo = socket.getaddrinfo(host, port)[0][-1]
		self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		self.secureRootSocket = None
		self.verbose = verbose

		
