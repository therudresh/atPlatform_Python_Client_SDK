import ssl
from .atConnection import AtConnection

"""
    Subclass of AtConnection representing a connection to the root server in the @ protocol.

    ...

    Attributes
    ----------
    __instance : AtRootConnection
        The singleton instance of AtRootConnection

    Methods
    -------
    getInstance(host='root.atsign.org', port=64, context=ssl.create_default_context(), verbose=False)
        Get an instance of AtRootConnection using the singleton pattern.
    __init__(self, host, port, context, verbose)
        Initialize the AtRootConnection object.
    connect(self)
        Establish a connection to the root server.
    parseRawResponse(rawResponse)
        Parse the raw response from the root server.
    findSecondary(atSign)
        Find the secondary server for the given @ sign on the root server.
    lookupAtSign(atSign)
        Lookup the @ sign on the root server and return the secondary server.
    """
class AtRootConnection(AtConnection):
	"""Subclass of AtConnection representing a connection to the root server in the @ protocol."""
    __instance = None


 """
        Get an instance of AtRootConnection using the singleton pattern.

        Parameters
        ----------
        host : str, optional
            The host name or IP address of the root server (default is 'root.atsign.org').
        port : int, optional
            The port number of the root server (default is 64).
        context : ssl.SSLContext, optional
            The SSL context for secure connections (default is ssl.create_default_context()).
        verbose : bool, optional
            Indicates if verbose output is enabled (default is False).

        Returns
        -------
        AtRootConnection
            An instance of AtRootConnection.
        """
    @staticmethod
    def getInstance(host='root.atsign.org', port=64, context=ssl.create_default_context(), verbose=False):
	  """Get an instance of AtRootConnection using the singleton pattern."""
        if AtRootConnection.__instance is None:
            AtRootConnection(host, port, context, verbose)
        return AtRootConnection.__instance

 """
        Initialize the AtRootConnection object.

        Parameters
        ----------
        host : str
            The host name or IP address of the root server.
        port : int
            The port number of the root server.
        context : ssl.SSLContext
            The SSL context for secure connections.
        verbose : bool
            Indicates if verbose output is enabled.
        """
    def __init__(self, host, port, context, verbose):
	"""Initialize the AtRootConnection object."""
        self.host = host
        self.port = port
        self.context = context
        self.verbose = verbose
        if AtRootConnection.__instance is not None:
            raise Exception("Singleton class - use AtRootConnection.getInstance() instead")
        else:
            AtRootConnection.__instance = self
            super().__init__(host, port, context, verbose)
    
    def connect(self):
	"""Establish a connection to the root server."""
        super().connect()
        if self.verbose:
            print("Root Connection Successful")

	"""
        Parse the raw response from the root server.

        Parameters
        ----------
        rawResponse : str
            The raw response received from the root server.

        Returns
        -------
        str
            The parsed response from the root server.
        """
    def parseRawResponse(self, rawResponse):
	"""Parse the raw response from the root server."""
        # responses from root are either 'null' or <host:port>
        
        if rawResponse.endswith("@"):
            rawResponse = rawResponse[:-1]

        return rawResponse.strip()
 """
        Find the secondary server for the given @ sign on the root server.

        Parameters
        ----------
        atSign : str
            The @ sign to lookup.

        Returns
        -------
        str
            The secondary server for the given @ sign.
        
        Raises
        ------
        Exception
            If the root lookup returns null or a malformed response is received.
        """
    def findSecondary(self, atSign):
	"""Find the secondary server for the given @ sign on the root server."""
        if not self.isConnected():
            try:
                self.connect()
            except Exception as e:
                # connect will only throw an AtException if authentication fails. Root connections do not require authentication.
                raise Exception(f"Root Connection failed - {e}")

        response = self.executeCommand(atSign.replace("@",""))
        
        if response == "null":
            raise Exception(f"Root lookup returned null for {atSign}")
        else:
            try:
                return response
            except ValueError as e:
                raise Exception(f"Received malformed response {response} from lookup of {atSign} on root server")

		"""
        Lookup the @ sign on the root server and return the secondary server.

        Parameters
        ----------
        atSign : str
            The @ sign to lookup.

        Returns
        -------
        str
            The secondary server for the given @ sign.

        Raises
        ------
        Exception
            If the root lookup returns null or a malformed response is received.
        """
    def lookupAtSign(self, atSign):
	"""Lookup the @ sign on the root server and return the secondary server."""
        return self.findSecondary(atSign).toString()

	
