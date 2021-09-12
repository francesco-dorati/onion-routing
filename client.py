import random
import socket
import base64
import json

from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MESSAGE = 'hello'
DESTINATION = '192.168.1.10:8083'

def main():
  # get the list of nodes
  with open('nodes.txt', 'r') as file:
    available_nodes = []
    for line in file:
      address, port = line.strip().split(':')
      available_nodes.append((address, port))

  # choose three random nodes
  nodes = random.sample(available_nodes, 3)

  # exchange keys
  keys = []
  for address, port in nodes:
    keys.append(get_key(address, port))
    print(keys)

  # construct message
  exit_node_message = Fernet(keys[2]).encrypt(
    json.dumps({
      'to': DESTINATION,
      'message': MESSAGE
    }).encode()
  ).decode()

  relay_node_message = Fernet(keys[1]).encrypt(
    json.dumps({
      'to': ':'.join(nodes[2]),
      'message': exit_node_message
    }).encode()
  ).decode()

  entry_node_message = Fernet(keys[0]).encrypt(
    json.dumps({
      'to': ':'.join(nodes[1]),
      'message': relay_node_message
    }).encode()
  ).decode()

  print(entry_node_message)

  # send message
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((nodes[0][0], int(nodes[0][1])))

    s.sendall(entry_node_message.encode())


def get_key(address: str, port: str):
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    print(address, port)
    s.connect((address, int(port)))

    public_key = random.randint(0, 999999)
    private_key = random.randint(0, 999999)

    s.sendall(public_key.to_bytes(1024, 'big'))
    external_public_key = int.from_bytes(s.recv(1024), 'big')

    partial_key = (public_key ** private_key) % external_public_key

    s.sendall(partial_key.to_bytes(1024, 'big'))
    external_partial_key = int.from_bytes(s.recv(1024), 'big')

    full_key = (external_partial_key ** private_key) % external_public_key
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        iterations=100000,
    )

    return base64.urlsafe_b64encode(kdf.derive(full_key.to_bytes(1024, 'big')))

    

if __name__ == '__main__':
  main()