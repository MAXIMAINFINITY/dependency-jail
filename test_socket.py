import socket

socket.create_connection(("example.com", 80), timeout=5)
print("Connected")
