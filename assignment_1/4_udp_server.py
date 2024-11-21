import socket


localIP = "127.0.0.1"
localPort = 20001
bufferSize = 1024

msgFromServer = "Reply from Server"
bytesToSend = str.encode(msgFromServer)

UDPServerSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

UDPServerSocket.bind((localIP, localPort))

# listening for incoming datagrams
bytesAddressPair = UDPServerSocket.recvfrom(bufferSize)

message = bytesAddressPair[0]
address = bytesAddressPair[1]

clientMsg = "Message from Client:{}".format(message.decode())
clientIP  = "Client IP Address:{}".format(address)

print(clientMsg)
print(clientIP)
