# Shilat Givati, 206377038, Amit Sharabi, 323784298

import random
import socket
import sys
import threading
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256

global messages, mutex
if len(sys.argv) < 2:
    print("Invalid input")
    exit(1)


def sender():
    global messages
    while True:
        time.sleep(60)  # wait for next round
        mutex.acquire()
        random.shuffle(messages)  # randomizes the messages list
        for m in messages:
            sender_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sender_sock.connect((m[0], m[1]))
            sender_sock.send(m[2])
            sender_sock.close()
        messages = []
        mutex.release()


def get_server_port():
    ips_file = open("ips.txt", "r")
    servers_info = ips_file.readlines()
    ips_file.close()
    server_info = servers_info[int(sys.argv[1]) - 1]
    server_info.replace('\n', '')
    return int(server_info.split(' ')[1])


def get_secret_key():
    sk_file = open("sk" + str(int(sys.argv[1])) + ".pem", "rb")
    secret_key_file = sk_file.read()
    sk_file.close()
    return secret_key_file


mix_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mix_socket.bind(('', get_server_port()))  # listen to any IP
mix_socket.listen(500)
messages = []
mutex = threading.Lock()
thread = threading.Thread(target=sender, args=())
thread.start()

while True:
    client_socket, client_address = mix_socket.accept()
    secret_key = serialization.load_pem_private_key(get_secret_key(), password=None, backend=default_backend())
    text = secret_key.decrypt(client_socket.recv(8192),
                              padding.OAEP(mgf=padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None))
    dest_ip = ""
    for i in range(4):
        dest_ip += str(int(text[i]))
        if i != 3:
            dest_ip += '.'
    dest_port = int.from_bytes(text[4:6], byteorder='big')  # port -> message
    text = text[6:]  # without port
    mutex.acquire()
    messages.append([dest_ip, dest_port, text])  # insert the to the list
    mutex.release()

    client_socket.close()
