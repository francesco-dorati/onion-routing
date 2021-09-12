import socket
import random
import base64
import sys
import json

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HOST = '192.168.1.10'
PORT = int(sys.argv[1])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  s.bind((HOST, PORT))
  print(f'Listening on port {PORT}...')

  public_key = random.randint(0, 999999)
  private_key = random.randint(0, 999999)

  s.listen()
  conn, addr = s.accept()

  s.listen()
  conn, addr = s.accept()

  external_public_key = int.from_bytes(conn.recv(1024), 'big')
  conn.sendall(public_key.to_bytes(1024, 'big'))

  partial_key = (external_public_key ** private_key) % public_key

  external_partial_key = int.from_bytes(conn.recv(1024), 'big')
  conn.sendall(partial_key.to_bytes(1024, 'big'))

  full_key = (external_partial_key ** private_key) % public_key

  kdf = PBKDF2HMAC(
      algorithm=hashes.SHA256(),
      length=32,
      salt=b'',
      iterations=100000,
  )

  key = base64.urlsafe_b64encode(kdf.derive(full_key.to_bytes(1024, 'big')))  
  

  # receive message
  s.listen()
  conn, addr = s.accept()

  encrypted_massage = conn.recv(1024)

  message = json.loads(Fernet(key).decrypt(encrypted_massage).decode())

  address, port = message['address'].split(':')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  s.connect((address, int(port)))
  s.sendall(message['message'].encode())



