import socket
import os


TCP_PORT = 20001
IP_ADDR = '127.0.0.1'
BUF_SIZE = 30

k = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

k.bind((IP_ADDR, TCP_PORT))

k.listen(1)

# accept connection for client
con, addr = k.accept()
print ('Connection Address is: ' , addr)

# recieve file name from client
fileName = con.recv(BUF_SIZE).decode()
fileSize = 0

if os.path.exists(fileName):
    # send file size
    fileSize = os.path.getsize(fileName)
    con.sendall(str(fileSize).encode())

    # send file data
    with open(fileName, 'rb') as file:
        while (True):
            data = file.read(BUF_SIZE)
            if not data:
                break
            con.sendall(data)
else:
    msg = "File Doesn't Exist!!".encode()
    con.send(msg)

print("total byte = ", fileSize)
con.close()
