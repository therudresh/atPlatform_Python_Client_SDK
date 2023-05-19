from .atRootConnection import AtRootConnection
from .atSecondaryConnection import AtSecondaryConnection
from .EncryptionUtil import EncryptionUtil
from .keysUtil import KeysUtil

class AtSign:
	"""
Represents an AtSign object.

Attributes
----------
atSign : str
    the AtSign name
verbose : bool
    flag indicating verbosity of output
rootConnection : AtRootConnection
    instance of AtRootConnection for root connection
secondaryConnection : AtSecondaryConnection
    instance of AtSecondaryConnection for secondary connection

Methods
-------
authenticate(keys)
    Authenticate the AtSign.
lookUp(key, location)
    Look up a key in the specified location.
plookUp(key, location)
    Look up a key in the specified location using a public lookup.
lLookUp(key)
    Look up a key in the local location.
slookUp(keys, key, location)
    Look up a key in itself using secure lookup.
update(key, value, location)
    Update a key-value pair in the specified location.
publicKeyUpdate(keyShare, location, time)
    Update a public key in the specified location.
sharedKeyUpdate(keyShare, location, time)
    Update a shared key in the specified location.
sUpdate(keys, key, value, location)
    Update a key-value pair in itself using secure update.
lUpdate(key, value)
    Update a key-value pair in the local location.
delete(key)
    Delete a key-value pair in itself.
__init__(atSign, verbose=False)
    Initialize the AtSign object.
"""
	  
	def authenticate(self, keys): ## `from` protocol
		 """
    Authenticate the AtSign.

    Parameters
    ----------
    keys : dict
        Dictionary containing the required keys for authentication

    Returns
    -------
    bool
        True if authentication is successful, False otherwise

    Raises
    ------
    Exception
        If authentication fails or an error occurs during the authentication process
    """
		privateKey = signature = None
		fromResponse = self.secondaryConnection.executeCommand(f"from:{self.atSign}")
	
		dataPrefix = "data:"
		if not fromResponse.startswith(dataPrefix):
			raise Exception(f"Invalid response to 'from' command: {repr(fromResponse)}")
		
		fromResponse = fromResponse[len(dataPrefix):]

		try:
			privateKey = EncryptionUtil.RSAKeyFromBase64(keys[KeysUtil.pkamPrivateKeyName])
		except:
			raise Exception("Failed to get private key from stored string")
		
		try:
			signature = EncryptionUtil.signSHA256RSA(fromResponse, privateKey)
		except:
			raise Exception("Failed to create SHA256 signature")
		
		pkamResponse = self.secondaryConnection.executeCommand(f"pkam:{signature}")

		if not pkamResponse.startswith("data:success"):
			raise Exception(f"PKAM command failed: {repr(pkamResponse)}")
		
		if self.verbose:
			print("Authentication Successful")
		
		return True

	 
	def lookUp(self, key : str, location : str):
		 """
    Look up a key in the specified location.

    Parameters
    ----------
    key : str
        The key to look up
    location : str
        The location to search for the key

    Returns
    -------
    str
        The value associated with the key if found, or an error message if the lookup fails
    """
		prefix = "data:"
		errorPrefix = "error:"
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation

		lookupResponse = self.secondaryConnection.executeCommand(f"lookup:{key}{uLocation}")
		
		if(not lookupResponse.startswith(prefix)):
			print("llookup failed")
		else:
			lookupResponse = lookupResponse[len(prefix):-(len(self.atSign) + 1)]

		if(lookupResponse.startswith(errorPrefix)):
			print("lookup failed")

		return lookupResponse

	 
	def plookUp(self, key : str, location : str):
		"""
    Look up a key in the specified location using a public lookup.

    Parameters
    ----------
    key : str
        The key to look up
    location : str
        The location to search for the key

    Returns
    -------
    str
        The value associated with the key if found, or an error message if the lookup fails
    """
		prefix = "data:"
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation

		lookupResponse = self.secondaryConnection.executeCommand(f"plookup:{key}{uLocation}")

		if(not lookupResponse.startswith(prefix)):
			print("plookup failed")
		else:
			lookupResponse = lookupResponse[len(prefix):-(len(self.atSign) + 1)]

		return lookupResponse

	
	def lLookUp(self, key : str):
		 """
    Look up a key in the local location.

    Parameters
    ----------
    key : str
        The key to look up

    Returns
    -------
    str
        The value associated with the key if found, or an error message if the lookup fails
    """
		prefix = "data:"
		lookupResponse = self.secondaryConnection.executeCommand(f"llookup:{key}{self.atSign}")

		if(not lookupResponse.startswith(prefix)):
			print("llookup failed")
		else:
			lookupResponse = lookupResponse[len(prefix):-(len(self.atSign) + 1)]

		return lookupResponse

	
	def slookUp(self, keys, key : str, location : str):
		 """
    Look up a key in itself using secure lookup.

    Parameters
    ----------
    keys : dict
        Dictionary containing the required keys for secure lookup
    key : str
        The key to look up
    location : str
        The location to search for the key

    Returns
    -------
    str
        The decrypted value associated with the key if found, or an error message if the lookup fails
    """
		prefix = "error:"
		uLocation = location
		
		if(location[0] == '@'):
			uLocation = uLocation[1:]

		lookupResponse = self.lookUp("shared_key", uLocation)

		if(lookupResponse.startswith(prefix)):
			return "ERROR: No sharedkeys to decrypt"
		else:
			sharedAESKey = EncryptionUtil.rsaDecryptFromBase64(lookupResponse, keys[KeysUtil.encryptionPrivateKeyName])

			lookupValueResponse = self.lookUp(key, uLocation)

			if(not lookupValueResponse.startswith(prefix)):
				decrypeddValue = EncryptionUtil.aesDecryptFromBase64(lookupValueResponse, sharedAESKey)
				return decrypeddValue;
			else:
				return "ERROR: No key found"

			
	def update(self, key : str, value : str, location : str):
		"""
    Update a key-value pair in the specified location.

    Parameters
    ----------
    key : str
        The key to update
    value : str
        The new value to associate with the key
    location : str
        The location to update the key-value pair

    Returns
    -------
    bool
        True if the update is successful, False otherwise
    """
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation
		updateResponse = self.secondaryConnection.executeCommand(f"update:{uLocation}:{key}{self.atSign} {value}")

		if("data:" in updateResponse):
			return True
		else:
			print(f"Update Failed: {updateResponse}")
			return False

		
	def publicKeyUpdate(self, keyShare, location : str, time : str):
		"""
    Update a public key in the specified location with a given time-to-refresh (TTR).

    Parameters
    ----------
    keyShare : str
        The new public key value to update
    location : str
        The location to update the public key
    time : str
        The time-to-refresh (TTR) value

    Returns
    -------
    bool
        True if the update is successful, False otherwise
    """
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation
		updateResponse = self.secondaryConnection.executeCommand(f"update:ttr:{time}:{uLocation}:publickey{self.atSign} {keyShare}")

		if("data:" in updateResponse):
			return True
		else:
			print(f"Update Failed: {updateResponse}")
			return False

		
	def sharedKeyUpdate(self, keyShare, location : str, time : str):
		"""
    Update a shared key in the specified location with a given time-to-refresh (TTR).

    Parameters
    ----------
    keyShare : str
        The new shared key value to update
    location : str
        The location to update the shared key
    time : str
        The time-to-refresh (TTR) value

    Returns
    -------
    bool
        True if the update is successful, False otherwise
    """
		uLocation = location
		if(location[0] != '@'):
			uLocation = "@" + uLocation
		updateResponse = self.secondaryConnection.executeCommand(f"update:ttr:{time}:{uLocation}:shared_key{self.atSign} {keyShare}")

		if("data:" in updateResponse):
			return True
		else:
			print(f"Update Failed: {updateResponse}")
			return False

		
	def sUpdate(self, keys, key : str, value : str, location : str):
		"""
    Securely update a key-value pair in itself.

    Parameters
    ----------
    keys : dict
        Dictionary containing the required keys for secure update
    key : str
        The key to update
    value : str
        The new value to associate with the key
    location : str
        The location to update the key-value pair

    Returns
    -------
    bool
        True if the update is successful, False otherwise
    """
		prefix = "error:"
		uLocation = location
		
		if(location[0] == '@'):
			uLocation = uLocation[1:]

		lookupResponse = self.lLookUp("shared_key." + uLocation)

		sharedAESKey = EncryptionUtil.generateAESKeyBase64()

		if(not lookupResponse.startswith(prefix)):
			sharedAESKey = EncryptionUtil.rsaDecryptFromBase64(lookupResponse, keys[KeysUtil.pkamPrivateKeyName])
		else:
			lookupPKResponse = self.plookUp("publickey", uLocation)
			if(not lookupPKResponse.startswith(prefix)):
				encryptedSharedAESKey = EncryptionUtil.rsaEncryptToBase64(sharedAESKey, lookupPKResponse)
				self.sharedKeyUpdate(encryptedSharedAESKey, location, "86400")
			else:
				return False

		encryptedValue = EncryptionUtil.aesEncryptFromBase64(value.encode('utf-8'), sharedAESKey)

		updateResponse = self.secondaryConnection.executeCommand(f"update:@{uLocation}:{key}{self.atSign} {encryptedValue}")

		if("data:" in updateResponse):
			return True
		else:
			print(f"Update Failed: {updateResponse}")
			return False

		return True

	
	def lUpdate(self, key : str, value : str):
		"""
    Update a key-value pair in the local location.

    Parameters
    ----------
    key : str
        The key to update
    value : str
        The new value to associate with the key

    Returns
    -------
    bool
        True if the update is successful, False otherwise
    """
		updateResponse = self.secondaryConnection.executeCommand(f"update:{key}{self.atSign} {value}")

		if("data:" in updateResponse):
			return True
		else:
			print(f"Self Update Failed: {updateResponse}")
			return False
		

	
	def delete(self, key : str):
			"""
    Delete a key-value pair in itself.

    Parameters
    ----------
    key : str
        The key to delete

    Returns
    -------
    bool
        True if the delete is successful, False otherwise
    """
		delResponse = self.secondaryConnection.executeCommand(f"delete:{key}{self.atSign}")

		if("data:" in delResponse):
			return True
		else:
			print(f"Self delete Failed: {delResponse}")
			return False


	## Good to have functions
	# def stats(self):
	# 	return True

	# def sync(self):
	# 	return True

	# def notify(self):
	# 	return True

	# def monitor(self):
	# 	return True

	
	def __init__(self, atSign, verbose=False):
		"""
    Initialize the AtSign object.

    Parameters
    ----------
    atSign : str
        The AtSign name
    verbose : bool, optional
        Flag indicating verbosity of output (default is False)
    """
		if(atSign[0] == '@'):
			self.atSign = atSign
		else:
			self.atSign = "@" + atSign
		self.verbose = verbose
		self.rootConnection = AtRootConnection.getInstance(verbose=verbose)
		
		#### Make this less error pruned :)
		secondaryAddress = self.rootConnection.findSecondary(atSign).split(":")
		
		self.secondaryConnection = AtSecondaryConnection(host=secondaryAddress[0], port=secondaryAddress[1], verbose=verbose)
		self.secondaryConnection.connect()
