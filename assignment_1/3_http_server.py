import socket
import os


TCP_PORT = 8081
IP_ADDR = '127.0.0.1'
BUF_SIZE = 1024

k = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

k.bind((IP_ADDR, TCP_PORT))

k.listen(1)

# accept connection for client
con, addr = k.accept()
print ('Connection Address is: ' , addr)

# recieve file name from client
req = con.recv(BUF_SIZE).decode()

header = req.split('\n')

if (len(header) > 0):
    print(header)
    fileName = header[0].split(' ')[1]

    if (fileName == '/'):
        fileName = '/index.html'
    
    fileName = fileName.lstrip('/')

    if os.path.exists(fileName):
        with open(fileName, 'rb') as file:
            res = file.read()
        
        # header
        resHeader = 'HTTP/1.1 200 OK\n'
        resHeader += 'Content-Type: text/html\n'
        resHeader += 'Content-Length: {}\n'.format(len(res))
        resHeader += '\n'
    else:
        with open('error.html', 'rb') as file:
            res = file.read()
        
        # header
        resHeader = 'HTTP/1.1 404 Not Found\n'
        resHeader += 'Content-Type: text/html\n'
        resHeader += 'Content-Length: {}\n'.format(len(res))
        resHeader += '\n'

    con.sendall(resHeader.encode() + res)

con.close()
