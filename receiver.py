# Shilat Givati, 206377038, Amit Sharabi, 323784298

import socket
import time
import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

if len(sys.argv) < 4:
    print("Invalid input")
    exit(1)

receiver_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
port = int(sys.argv[3])
receiver_socket.bind(('', port))  # listen to any IP
receiver_socket.listen(500)

password = sys.argv[1]
salt = sys.argv[2]
key_derivation_function = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt.encode(),
                                     iterations=100000, backend=default_backend())
key = Fernet(base64.urlsafe_b64encode(key_derivation_function.derive(password.encode())))

# receive messages
while True:
    client_socket, client_address = receiver_socket.accept()
    origin_msg = key.decrypt(client_socket.recv(8192)).decode("utf-8")

    # print the message and time
    print(origin_msg, time.strftime("%H:%M:%S", time.localtime(time.time())))
    client_socket.close()
