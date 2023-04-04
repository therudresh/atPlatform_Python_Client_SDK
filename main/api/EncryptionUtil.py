import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

def signSHA256RSA(input_data, private_key):
    hash_data = SHA256.new(input_data.encode('utf-8'))
    signature = pkcs1_15.new(private_key).sign(hash_data)

    return base64.b64encode(signature).decode('utf-8')

def decryptAesFromBase64(cipher_text_base64, key_base64):
    key = base64.b64decode(key_base64)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = base64.b64decode(cipher_text_base64)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode('utf-8')

def privateKeyFromBase64(s):
    key_bytes = base64.b64decode(s.encode('utf-8'))
    key_spec = RSA.import_key(key_bytes)
    return key_spec

