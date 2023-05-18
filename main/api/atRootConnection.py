import ssl
from .atConnection import AtConnection


class AtRootConnection(AtConnection):
	"""Subclass of AtConnection representing a connection to the root server in the @ protocol."""
    __instance = None

    @staticmethod
    def getInstance(host='root.atsign.org', port=64, context=ssl.create_default_context(), verbose=False):
	  """Get an instance of AtRootConnection using the singleton pattern."""
        if AtRootConnection.__instance is None:
            AtRootConnection(host, port, context, verbose)
        return AtRootConnection.__instance

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

    def parseRawResponse(self, rawResponse):
	"""Parse the raw response from the root server."""
        # responses from root are either 'null' or <host:port>
        
        if rawResponse.endswith("@"):
            rawResponse = rawResponse[:-1]

        return rawResponse.strip()

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

    def lookupAtSign(self, atSign):
	"""Lookup the @ sign on the root server and return the secondary server."""
        return self.findSecondary(atSign).toString()

	
