import rsa
import base64
from cryptography.hazmat.primitives import serialization


def RSA_2048__key_generation():
    (publickey,privatekey)=rsa.newkeys(2048)
    return (publickey,privatekey)

def RSA_2048_encryption(message,publickey):
    encrypted_mess=rsa.encrypt(message,publickey)
    return encrypted_mess

def RSA_2048_decryption(message,privatekey):
  decrypted_mess=rsa.decrypt(message,privatekey)
  return decrypted_mess

def RSA_sign(message,privatekey):
  encoded_mess=message.encode()
  signature=rsa.sign(encoded_mess,privatekey,'SHA-256')
  return signature


def RSA_verify(message,signature,publickey):
  encoded_mess=message.encode()
  try:
    rsa.verify(encoded_mess, signature, publickey)
    return True
  except:
    return False


def base64_encode(message):
  encoded_mess_ascii=message.encode('ascii')
  encoded_mess=base64.b64encode(encoded_mess_ascii)
  encoded_mess_base64=encoded_mess.decode('ascii')
  return encoded_mess_base64


def base64_decode(message):
  decoded_mess_ascii=message.encode('ascii')
  decoded_mess=base64.b64decode(decoded_mess_ascii)
  decodedmess_base64=base64.b64decode(decoded_mess)
  return decodedmess_base64




# sample="hello world"
# keys=RSA_2048__key_generation()
# encrypted_string=RSA_2048_encryption(sample.encode(),keys[0])
# print(encrypted_string)
# decrypted_string=RSA_2048_decryption(encrypted_string,keys[1])
# print(decrypted_string.decode())

