from OpenSSL import crypto, SSL

# Create a new key pair
key = crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 2048)

# Create a self-signed certificate
cert = crypto.X509()
cert.get_subject().C = "US" # Country
cert.get_subject().ST = "MA" # State
cert.get_subject().L = "Boston" # Locality
cert.get_subject().O = "Umass" # Organization
cert.get_subject().OU = "CS Department" # Organizational Unit
cert.get_subject().CN = "root.atsign.org" # Common Name
cert.set_serial_number(1000)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(365 * 24 * 60 * 60) # Expires in 1 year
cert.set_issuer(cert.get_subject()) # Self-signed
cert.set_pubkey(key)
cert.sign(key, 'sha256')

# Write the key and certificate to disk
with open("private_key.pem", "wb") as f:
    f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
with open("certificate.pem", "wb") as f:
    f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
