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
		# Set up connection to secondary server
		# self.atConnection = AtConnection
