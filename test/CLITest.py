import time
import usocket as socket
# import ussl as ssl
import sys
import ssl

atSign = '27barracuda'

print('Finding secondary for @' + atSign + '...')
hostname = 'root.atsign.org'
port = 64

a = socket.getaddrinfo(hostname, port)[0][-1]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

with open("certificate.pem", "rb") as f:
    cert = f.read()
with open("private_key.pem", "rb") as f:
    key = f.read()

try:
    s.connect(a)
except OSError as e:
    if str(e) == '119':
        print("In Progress")
    else:
        raise e


context = ssl.create_default_context()
# context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# context.load_cert_chain(certfile="certificate.pem", keyfile="private_key.pem")

# s.setblocking(False)
ss = context.wrap_socket(s, server_hostname=hostname, do_handshake_on_connect = True)
# ss = s

print('Writing to socket: @'+ atSign)
ss.write((atSign + "\n").encode())
# ss.send((atSign + "\r\n").encode())
# ss.send(b"27barracuda")
# ss.send(b"\n")
# ss.flush()
time.sleep(5)

response = b''
# data = ss.read()
data = ss.read(2048)
response += data

print('TLS the 1st' + response.decode())

secondary = response.decode().replace('@', '')
secondary = secondary.replace('\r\n', '')

ss.write((response.decode() + atSign + "\n").encode())
time.sleep(5)

response = b''
# data = ss.read()
data = ss.read(2048)
response += data

print('TLS the 2nd' + response.decode())

ss.close()
print('Address found: %s' % secondary)