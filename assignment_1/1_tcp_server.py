import socket


TCP_PORT = 20001
IP_ADDR = '127.0.0.1'
BUF_SIZE = 30

k = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

k.bind((IP_ADDR, TCP_PORT))

k.listen(1)

# accept connection for client
con, addr = k.accept()
print ('Connection Address is: ' , addr)

# recieve message from client
data = con.recv(BUF_SIZE)
print ("Received data", data.decode())

# send message to client
msg = "Hi".encode()
con.send(msg)

con.close()
