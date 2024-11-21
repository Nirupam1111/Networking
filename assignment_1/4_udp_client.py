import socket


serverAddressPort = ("127.0.0.1", 20001)
bufferSize = 1024

UDPClientSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

# send data to server
msgFromClient = "Hello UDP Server: I am UDP Client1"
bytesToSend = str.encode(msgFromClient)

UDPClientSocket.sendto(bytesToSend, serverAddressPort)
