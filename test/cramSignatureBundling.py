import base64
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA

def sign_sha256_rsa(input_data, private_key):
    # Compute the hash of the input data using SHA-256
    hash_data = SHA256.new(input_data.encode('utf-8'))

    # Sign the hash using the private key
    signature = pkcs1_15.new(private_key).sign(hash_data)

    return base64.b64encode(signature).decode('utf-8')

if __name__ == "__main__":
    input_data = "Hello, world!"
    private_key = RSA.generate(2048)

    signature = sign_sha256_rsa(input_data, private_key)
    print(signature)