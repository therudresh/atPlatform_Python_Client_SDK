# -*- coding: utf-8 -*-


import base64
import secrets
import proj_4a_AES
import proj_4a_RSA

aes_key = secrets.token_bytes(32)

user_input = input("Please enter a string: ")
sample_text = bytes(user_input, 'utf-8')
# sample_text=b"Hi, this is a texting string"
nonce_1 = secrets.token_bytes(16)
AES_enc_sample_text = proj_4a_AES.aes_ctr_256_encrypt(sample_text, aes_key, nonce_1)




aes_key_encoded=base64.b64encode(aes_key)

rsa_keys=proj_4a_RSA.RSA_2048__key_generation()


encrypted_aes_key=proj_4a_RSA.RSA_2048_encryption(aes_key_encoded,rsa_keys[0])

decrypted_aes_key=proj_4a_RSA.RSA_2048_decryption(encrypted_aes_key,rsa_keys[1])
decrypted_aes_key_decoded=base64.b64decode(decrypted_aes_key)


print("=================Encryption details=================")
print("AES encrypted sample text : " + AES_enc_sample_text.decode('utf-8'))
print("AES key: " + aes_key_encoded.decode('utf-8'))
print("Encrypted AES key : "+ base64.b64encode(encrypted_aes_key).decode('utf-8'))

print("=================Result=================")
print("Final decrypted message : " + proj_4a_AES.aes_ctr_256_decrypt(AES_enc_sample_text, decrypted_aes_key_decoded, nonce_1).decode('utf-8'))