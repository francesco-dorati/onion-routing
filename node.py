import socket
import random
import base64
import sys
import json

# todo implement diffie hellman through tor

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

HOST = '192.168.1.10'
PORT = int(sys.argv[1])

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
  key = None

  s.bind((HOST, PORT))
  s.listen()
  print(f'Listening on port {PORT}...\n')

  while True:
    conn, addr = s.accept()

    data = conn.recv(1024)
    if not data:
      continue

    if not key:
      # exchange keys
      print(f'Exchanging keys with {addr[0]}:{addr[1]}...')
      priv = random.randint(0, 999999)
      kdf = PBKDF2HMAC(
          algorithm=hashes.SHA256(),
          length=32,
          salt=b'',
          iterations=100000,
      )

      e_pub = int.from_bytes(data, 'big')
      
      pub = random.randint(0, 999999)
      conn.sendall(pub.to_bytes(1024, 'big'))

      e_part = int.from_bytes(conn.recv(1024), 'big')

      part = (e_pub ** priv) % pub
      conn.sendall(part.to_bytes(1024, 'big'))

      full = (e_part ** priv) % pub

      key = base64.urlsafe_b64encode(kdf.derive(full.to_bytes(1024, 'big')))

      print(key.decode() + '\n')
      continue
    
    # receive message
    message = json.loads(
      Fernet(key).decrypt(data).decode() 
    )

    address, port = message['address'].split(':')

    print(f'Relaying message to {address}:{port}...')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sender:
      sender.connect((address, int(port)))
      sender.sendall(message['message'].encode())
    print('Message sent.\n')

    print(f'Waiting for other connections...\n')


