# Shilat Givati, 206377038, Amit Sharabi, 323784298

import base64
import socket
import sys
import time

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key


# encrypt data by the server public key
def encrypt_data(plaintext, server):
    pem_file = "pk" + server + ".pem"
    pem_file = open(pem_file, "r")
    public_key = pem_file.read()
    pem_file.close()
    public_key = load_pem_public_key(public_key.encode(), backend=default_backend())
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def send_messages(messages, servers_info):
    for message in messages:
        to_send = message.split(" ")
        to_send[6].replace('\n', '')
        # parsing message
        password = str.encode(to_send[3])
        salt = str.encode(to_send[4])
        data = str.encode(to_send[0])

        # generate symmetric key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        k = base64.urlsafe_b64encode(kdf.derive(password))
        f = Fernet(k)
        data = f.encrypt(data)

        # parsing dest IP and PORT
        server_port = int(to_send[6]).to_bytes(2, 'big')
        server_ip = to_send[5].split(".")
        temp_ip = b''
        for num in server_ip:
            temp_ip += int(num).to_bytes(1, 'big')
        server_ip = temp_ip
        plaintext = server_ip + server_port + data

        # sending path
        path = to_send[1]
        path = path.split(",")
        path.reverse()

        ciphertext = encrypt_data(plaintext, path[0])
        server_ip, server_port = servers_info[int(path[0]) - 1].split(" ")
        path = path[1:]
        for i in range(len(path)):
            server_port_bytes = int(server_port).to_bytes(2, 'big')
            temp_ip = b''
            ip_part = server_ip.split(".")
            for num in ip_part:
                temp_ip += int(num).to_bytes(1, 'big')
            server_ip_bytes = temp_ip
            plaintext = server_ip_bytes + server_port_bytes + ciphertext  # chaining data
            ciphertext = encrypt_data(plaintext, path[i])

            server_ip, server_port = servers_info[int(path[i]) - 1].split(" ")

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server_ip, int(server_port)))
            s.send(ciphertext)
            s.close()
        except ConnectionError:
            print("Connection Error")


x = sys.argv[1]

file = open("messages" + x + ".txt")
messages = file.readlines()
file.close()

servers_file = open("ips.txt", "r")
servers_info = servers_file.readlines()
servers_file.close()

# get all servers info
for i in range(len(servers_info)):
    if servers_info[i][-1] == '\n':
        servers_info[i] = servers_info[i][:-1]

# get all messages to send
messages_by_round = {}
for message in messages:
    m = message.split(" ")
    round = m[2]
    if int(round) not in messages_by_round:
        messages_by_round[int(round)] = [message.replace('\n', '')]
    else:
        messages_by_round[int(round)].append(message.replace('\n', ''))

messages_by_round = sorted(messages_by_round.items())  # sort by round

first_round = time.time()
round = 0
for message in messages_by_round:
    time.sleep(60 * (message[0] - round))  # wait for next round
    round = message[0]
    if message[0] == round:
        send_messages(message[1], servers_info)
