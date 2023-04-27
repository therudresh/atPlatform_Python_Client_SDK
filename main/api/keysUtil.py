import os
import json
import base64
from typing import Dict, Tuple

from .EncryptionUtil import EncryptionUtil


class KeysUtil:
    expectedKeysFilesLocation = os.path.expanduser("~/.atsign/keys/")
    legacyKeysFilesLocation = os.path.join(os.getcwd(), "keys")
    keysFileSuffix = "_key.atKeys"

    pkamPublicKeyName = "aesPkamPublicKey"
    pkamPrivateKeyName = "aesPkamPrivateKey"
    encryptionPublicKeyName = "aesEncryptPublicKey"
    encryptionPrivateKeyName = "aesEncryptPrivateKey"
    selfEncryptionKeyName = "selfEncryptionKey"

    @staticmethod
    def saveKeys(atSign, keys):
        if atSign[0] != "@": atSign = f"@{atSign}"
        expectedKeysDirectory = os.path.dirname(KeysUtil.expectedKeysFilesLocation)
        os.makedirs(expectedKeysDirectory, exist_ok=True)
        file = KeysUtil.getKeysFile(atSign, KeysUtil.expectedKeysFilesLocation)
        print(f"Saving keys to {file}")

        selfEncryptionKey = keys[KeysUtil.selfEncryptionKeyName]
        encryptedKeys = {
            KeysUtil.selfEncryptionKeyName: selfEncryptionKey,
            KeysUtil.pkamPublicKeyName: EncryptionUtil.aesEncryptFromBase64(keys[KeysUtil.pkamPublicKeyName], selfEncryptionKey),
            KeysUtil.pkamPrivateKeyName: EncryptionUtil.aesEncryptFromBase64(keys[KeysUtil.pkamPrivateKeyName], selfEncryptionKey),
            KeysUtil.encryptionPublicKeyName: EncryptionUtil.aesEncryptFromBase64(keys[KeysUtil.encryptionPublicKeyName], selfEncryptionKey),
            KeysUtil.encryptionPrivateKeyName: EncryptionUtil.aesEncryptFromBase64(keys[KeysUtil.encryptionPrivateKeyName], selfEncryptionKey),
        }

        jsonData = json.dumps(encryptedKeys, indent=4)
        with open(file, "w") as f:
            f.write(jsonData)

    @staticmethod
    def loadKeys(atSign):
        if atSign[0] != "@": atSign = f"@{atSign}"
        file = KeysUtil.getKeysFile(atSign, KeysUtil.expectedKeysFilesLocation)
        if not os.path.exists(file):
            file = KeysUtil.getKeysFile(atSign, KeysUtil.legacyKeysFilesLocation)
            if not os.path.exists(file):
                raise Exception(f"loadKeys: No file called {atSign}{KeysUtil.keysFileSuffix} at {KeysUtil.expectedKeysFilesLocation} or {KeysUtil.legacyKeysFilesLocation}\n"
                                            "\t Keys files are expected to be in ~/.atsign/keys/ (canonical location) or ./keys/ (legacy location)")

        with open(file) as f:
            encryptedKeys = json.load(f)

        selfEncryptionKey = encryptedKeys[KeysUtil.selfEncryptionKeyName]
        keys = {
            KeysUtil.selfEncryptionKeyName: selfEncryptionKey,
            KeysUtil.pkamPublicKeyName: EncryptionUtil.aesDecryptFromBase64(encryptedKeys[KeysUtil.pkamPublicKeyName], selfEncryptionKey),
            KeysUtil.pkamPrivateKeyName: EncryptionUtil.aesDecryptFromBase64(encryptedKeys[KeysUtil.pkamPrivateKeyName], selfEncryptionKey),
            KeysUtil.encryptionPublicKeyName: EncryptionUtil.aesDecryptFromBase64(encryptedKeys[KeysUtil.encryptionPublicKeyName], selfEncryptionKey),
            KeysUtil.encryptionPrivateKeyName: EncryptionUtil.aesDecryptFromBase64(encryptedKeys[KeysUtil.encryptionPrivateKeyName], selfEncryptionKey),
        }

        return keys
    
    @staticmethod
    def getKeysFile(atSign, folderToLookIn):
        return os.path.join(folderToLookIn, "{}{}".format(atSign, KeysUtil.keysFileSuffix))