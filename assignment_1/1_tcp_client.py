import socket


TCP_PORT = 20001
IP_ADDR = '127.0.0.1'
BUF_SIZE = 1024

k = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

k.connect((IP_ADDR, TCP_PORT))

# send message to server
MSG = "Hello"
k.send(MSG.encode())

# recieve reply from server
data = k.recv(BUF_SIZE)
print(data.decode())

k.close()
