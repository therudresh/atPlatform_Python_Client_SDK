# atPlatform_Python_Client_SDK

**Project Description**: SDK for atPlatform protocols.

## How to Use

Create keys directory inside root folder and copy the atSign .atKeys files to run the code.

### Terminal

```python
>>> from main.api.AtSign import AtSign
>>> from main.api.keysUtil import KeysUtil

# Load keys for @amateur93
>>> amateur93Keys = KeysUtil.loadKeys("@amateur93")

# Create AtSign object for @amateur93
>>> amateur93Atsign = AtSign("@amateur93")

# Authenticate @amateur93
>>> amateur93Atsign.authenticate(amateur93Keys)
True

# Update key-value pair in local location
>>> amateur93Atsign.lUpdate("foo", "bar")
True

# Look up key in local location
>>> amateur93Atsign.lLookUp("foo")
'bar'

# Load keys for @universal27aloo
>>> universal27alooKeys = KeysUtil.loadKeys("@universal27aloo")

# Create AtSign object for @universal27aloo
>>> universal27alooAtsign = AtSign("@universal27aloo")

# Authenticate @universal27aloo
>>> universal27alooAtsign.authenticate(universal27alooKeys)
True

# Update key-value pair in specified location
>>> universal27alooAtsign.update("hello", "world", "@amateur93")
True

# Look up key in specified location
>>> amateur93Atsign.lookUp("hello", "@universal27aloo")
'world'

# Securely update key-value pair in itself
>>> amateur93Atsign.sUpdate(amateur93Keys, "foo", "bar", "universal27aloo")
True

# Securely look up key in itself
>>> universal27alooAtsign.slookUp(universal27alooKeys, "foo", "amateur93")
'bar'
```

## API Description

The project provides an `AtSign` object that allows interacting with the AtSign protocol. The main attributes and methods of the `AtSign` object are described below:

### Attributes

- `atSign`: A string representing the AtSign name.
- `verbose`: A boolean flag indicating the verbosity of output.
- `rootConnection`: An instance of `AtRootConnection` for root connection.
- `secondaryConnection`: An instance of `AtSecondaryConnection` for secondary connection.

### Methods

- `authenticate(keys)`: Authenticates the AtSign using the provided keys.
- `lookUp(key, location)`: Looks up a key in the specified location.
- `plookUp(key, location)`: Looks up a key in the specified location using a public lookup.
- `lLookUp(key)`: Looks up a key in the local location.
- `slookUp(keys, key, location)`: Looks up a key in itself using secure lookup.
- `update(key, value, location)`: Updates a key-value pair in the specified location.
- `publicKeyUpdate(keyShare, location, time)`: Updates a public key in the specified location.
- `sharedKeyUpdate(keyShare, location, time)`: Updates a shared key in the specified location.
- `sUpdate(keys, key, value, location)`: Updates a key-value pair in itself using secure update.
- `lUpdate(key, value)`: Updates a key-value pair in the local location.
- `delete(key)`: Deletes a key-value pair in itself.
- `__init__(atSign, verbose=False)`: Initializes the AtSign object.
