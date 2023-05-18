import ssl
from .atConnection import AtConnection


class AtSecondaryConnection(AtConnection):
    """Subclass of AtConnection representing a connection to a secondary server in the @ protocol."""

    def __init__(self, host, port, context=ssl.create_default_context(), verbose=False):
        """Initialize the AtSecondaryConnection object."""
        super().__init__(host, port, context, verbose)

    def connect(self):
        """Establish a connection to the secondary server."""
        super().connect()
        if self.verbose:
            print(f"Secondary Connection Successful")

    def parseRawResponse(self, rawResponse):
        """Parse the raw response from the secondary server."""
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
