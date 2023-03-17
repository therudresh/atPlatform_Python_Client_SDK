import time
import usocket as socket
# import ussl as ssl
import sys

atSign = 'armed86snoware'

print('Finding secondary for @' + atSign + '...')
a = socket.getaddrinfo('root.atsign.org', 64)[0][-1]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 

try:
    s.connect(a)
except OSError as e:
    if str(e) == '119':
        print("In Progress")
    else:
        raise e
    
s.setblocking(False)
# ss = ssl.wrap_socket(s, do_handshake = True)
ss = s

# ss.write((atSign + "\r\n").encode())
ss.send((atSign + "\r\n").encode())
time.sleep(5)

response = b''
# data = ss.read()
data = ss.recv(2048)
response += data

print(data)

secondary = response.decode().replace('@', '')
secondary = secondary.replace('\r\n', '')

ss.close()
print('Address found: %s' % secondary)