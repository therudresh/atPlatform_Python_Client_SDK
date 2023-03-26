from AtConnection import atConnection

class AtSign:
	atSign = ""
	
	atConnection = None

	keyManager = None

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


	def __init__(self, atSign):
		self.atSign = atSign
		  # Set up socket connection to root server
        root_server_address = #root_address
        root_server_port = 3000
        root_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        root_server_socket.connect((root_server_address, root_server_port))

        # Set up socket connection to secondary server domain
        secondary_server_address = #secondaryaddress
        secondary_server_port = 8000
        secondary_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        secondary_server_socket.connect((secondary_server_address, secondary_server_port))

        # Set up socket connection with secondary server
        secondary_server_socket.sendall('CONNECT {}'.format(atSign).encode())
        response = secondary_server_socket.recv(1024)
        if response == b'OK':
            self.atConnection = AtConnection(root_server_socket, secondary_server_socket)
        else:
            raise ConnectionError('Failed to connect to secondary server')
