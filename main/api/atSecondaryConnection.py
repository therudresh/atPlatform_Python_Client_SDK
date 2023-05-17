import ssl
from .atConnection import AtConnection

# The AtSecondaryConnection class is a subclass of AtConnection and represents a connection to a secondary server in the @ protocol. It inherits methods from the parent class to establish a connection, send commands, and parse responses. It also inherits executeCommand(), isConnected(), disconnect(), write(), read(), and str() methods.
class AtSecondaryConnection(AtConnection):

    def __init__(self, host, port, context=ssl.create_default_context(), verbose=False):
        super().__init__(host, port, context, verbose)

    def connect(self):
        super().connect()
        if self.verbose:
            print(f"Secondary Connection Successful")

    def parseRawResponse(self, rawResponse):
        if rawResponse.endswith("@"):
            rawResponse = rawResponse[:-1]
        rawResponse = rawResponse.strip()
        
        return rawResponse
        # if "data:" in rawResponse:
        #     return rawResponse[rawResponse.index("data:"):]
        # elif "error:" in rawResponse:
        #     return rawResponse[rawResponse.index("error:"):]
        # elif "notification:" in rawResponse:
        #     return rawResponse[rawResponse.index("notification:"):]
        # else:
        #     raise ValueError(f"Invalid response from server: {rawResponse}")