import socket


TCP_PORT = 20001
IP_ADDR = '127.0.0.1'
BUF_SIZE = 1024

k = socket.socket (socket.AF_INET, socket.SOCK_STREAM)

k.connect((IP_ADDR, TCP_PORT))

# send file name to server
fileName = input("enter file name: ")
print(fileName)
k.send(fileName.encode())

# recieve file size from server
fileSize = k.recv(BUF_SIZE).decode()

if fileSize == "File Doesn't Exist!!":
    print(fileSize)
else:
    fileSize = int(fileSize)

    # accept file data
    with open("received_" + fileName, 'wb') as file:
        dataReceived = 0
        while dataReceived < fileSize:
            data = k.recv(BUF_SIZE)
            if not data:
                break
            file.write(data)
            dataReceived += len(data)

k.close()
