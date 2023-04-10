import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

from Crypto.Util import Counter

import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def translate(s, map):
    import io
    sb = io.StringIO()
    for c in s:
        v = ord(c)
        if v in map:
            v = map[v]
            if isinstance(v, int):
                sb.write(chr(v))
            elif v is not None:
                sb.write(v)
        else:
            sb.write(c)
    return sb.getvalue()

def b42_urlsafe_encode(payload):
    return translate(binascii.b2a_base64(payload)[:-1].decode('utf-8'),{ ord('+'):'-', ord('/'):'_' })

def signSHA256RSA(input_data, private_key):
    hash_data = SHA256.new(input_data.encode('utf-8'))
    signature = pkcs1_15.new(private_key).sign(hash_data)
    return base64.b64encode(signature).decode('utf-8')

def verify(public_key, signature, data):
    key_bytes = base64.b64decode(public_key.encode('utf-8'))
    key_spec = RSA.import_key(key_bytes)
    try:
        pkcs1_15.new(key_spec).verify(SHA256.new(data.encode('utf-8')), signature)
        print("Signature Valid")
    except Exception as e:
        print(e, "Signature Invalid")
    return key_spec

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import binascii

iv = b'\x00'*16

def aesDecryptFromBase64(encryptedText, selfEncryptionKey):
    ciphertext = binascii.a2b_base64(encryptedText)
    key = binascii.a2b_base64(selfEncryptionKey)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the plaintext using PKCS7 padding
    padder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = padder.update(plaintext) + padder.finalize()

    # Print the decrypted plaintext
    return plaintext.decode('utf-8')

# def aesDecryptFromBase64(cipher_text_base64, key_base64):
#     key = base64.b64decode(key_base64)
#     ciphertext = base64.b64decode(cipher_text_base64)
#     nonce = secrets.token_bytes(16)
#     cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
#     decryptor = cipher.decryptor()
#     plaintext = decryptor.update(base64.b64decode(ciphertext)) + decryptor.finalize()
#     return plaintext.decode(encoding="utf-8")
    
    # key = base64.b64decode(key_base64)
    # iv = Random.new().read(16)
    # cipher = AES.new(key, AES.MODE_CTR)
    # ciphertext = base64.b64decode(cipher_text_base64)
    # decrypted = cipher.decrypt(ciphertext)
    # return decrypted.decode('utf-8')


    # key = base64.b64decode(key_base64)
    # iv = hex_str_to_bytes("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
    # cipher = AES.new(key, AES.MODE_CTR, nonce=iv)
    # ciphertext = base64.b64decode(cipher_text_base64)
    # decrypted = cipher.decrypt(ciphertext)
    # # print("***$$$", decrypted)
    # return decrypted.decode(encoding="utf-8")

def privateKeyFromBase64(s):
    key_bytes = base64.b64decode(s.encode('utf-8'))
    key_spec = RSA.import_key(key_bytes)
    return key_spec

# from cryptography.hazmat.primitives import hashes, serialization
# from cryptography.hazmat.primitives.asymmetric import padding
# from cryptography.hazmat.backends import default_backend

# def privateKeyFromBase64(s):
#     key_bytes = base64.b64decode(s.encode('utf-8'))
#     print("WWWWw   ", key_bytes)
#     private_key = serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())
#     return private_key
