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

class Client:
  def __init__(self):
    # get the list of nodes
    with open('nodes.txt', 'r') as file:
      nodes = []
      for line in file:
        address, port = line.strip().split(':')
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
          try:
            node = (address, int(port))
            nodes.append(node)
          except ConnectionRefusedError:
            pass

    # not enough nodes
    if len(nodes) < 3:
      print('Active nodes:')
      for node in nodes:
        print(f'{node[0]}:{node[1]}')
      print('\n3 nodes required.')
      print('Exiting...')
      exit(1)

    # choose three random nodes
    self.nodes = [{'address': address} for address in random.sample(nodes, 3)]

    print('Route:')
    for node in self.nodes:
        print(f"{node['address'][0]}:{node['address'][1]}")

    # exchange keys with nodes
    print('\nExchanging keys...')
    for node in self.nodes:
      print(f"{node['address'][0]}:{node['address'][1]}")
      node['key'] = self.__exchange_key(*node['address'])
      print(node['key'].decode() + '\n') 

  def send(self, address: str, message: str):
    # create leyered message
    print('\nCreating message...')
    packet = Fernet(self.nodes[0]['key']).encrypt(
      json.dumps({

        'address': ':'.join(map(str, self.nodes[1]['address'])),
        'message': Fernet(self.nodes[1]['key']).encrypt(
          json.dumps({

            'address': ':'.join(map(str, self.nodes[2]['address'])),
            'message': Fernet(self.nodes[2]['key']).encrypt(
              json.dumps({

                'address': address,
                'message': message
              
              }).encode()
            ).decode()
          
          }).encode()
        ).decode()
      
      }).encode()
    )

    # send message
    print('\nSending message...')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.connect(self.nodes[0]['address'])
      s.sendall(packet)
    print('Message sent.')


  def __exchange_key(self, address: str, port: int) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.connect((address, port))

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
  c = Client()
  c.send(DESTINATION, MESSAGE)