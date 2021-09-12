import socket


HOST = '192.168.1.10'
PORT = 8083

# receive messages
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  s.bind((HOST, PORT))

  s.listen()

  conn, addr = s.accept()

  print('Message: ' + conn.recv(1024).decode())
  print('From: ', addr)
