
# Mix servers

#### Contributes

* Amit Sharabi
* Shilat Givati

Mix server and clients that transmit messages between them in an encrypted and anonymous manner.

1. [General](#General)
    - [Background](#background)
    - [Project Stucture](https://github.com/amit164/Mix-servers/blob/main/README.md#project-description)
    - [Message forwarding](https://github.com/amit164/Mix-servers/blob/main/README.md#message-forwarding)
2. [Installation](#installation)

## General

### Background
Mix servers receive and accumulate encrypted messages from many clients, decrypt the messages and deliver them to their destination once a minute. You can create a Mix server chain by creating a message in a way that causes one Mix server to send the message to another Mix server so that the message eventually reaches its destination. Because the messages accumulate on the servers and are sent once a minute, messages can be sent anonymously between a pair of clients.

### Project Structure


* The **send client** sends the messages, receives as argument number X.
* The **receive client** receives a pair of arguments, salt and a password. Through them he will decipher the message conveyed to him.
* The **Mix server** receives and sends messages, receives as argument number Y.

### Message forwarding
The sending client reads from a file named ```messagesX.txt```. The file contains lines in the following format (where each line is a message sent by the client ):
[message] [path] [round] [password] [salt] [dest_ip] [dest_port]
* **message** - is the message to be sent
* **path** - is the server path that the message must transmit
* **round** - In which rotation the message should be sent
* **password** - Password to create a symmetric key
* **salt** - to create a symmetrical key
* **dest_ip** - The final destination address
* **dest_port** - The final destination port

Sample line:
``` 
cccc 3,2,1 0 password password 127.0.0.1 5000
```
The message being delivered is ```cccc```. It will be transmitted through the mix servers in order. That is, 3 who will forward the message to server number 2 who will forward the message to server number 1 who will finally forward the message to the receiving client - to the destination (located in the written IP and port). The ``password`` and the ``salt`` is intended for symmetrical encryption between the sender and the receiver. The ``round`` is the number of minutes the sending client has to wait before sending the message.

The sending client also loads an ```ips.txt``` file containing the server information as well as ``pkY.pem`` files containing the public keys of the mix servers.

The message that the client sends is structured as follows: Encryption of the initial message (_a.k.a **plaintxet**_) with the ```symmetric key```. Then, chain the ``IP`` and ``port`` of the target computer (receiving client). This message is encrypted with the ``public key`` of the last Mix server in the chain. And then chain the ``IP`` and ``port`` of the last Mix server. This message is encrypted again and again (each time the addresses of the next Mix server in the chain) until the first Mix server to which the message is sent.

The Mix server loads a file named ``skY.pem``. This file contains its **private key** (to decrypt the messages sent to it).

The receiving client decrypts the encryption (with the **symmetric key**) and prints the message.

## Installation

1. Open the terminal
2. Clone the project by:
	```
	$ git clone https://github.com/amit164/Mix-servers.git
	```	
3. Run the receiver client:
	```
	$ python3 receiver.py password password 5000
	 ```
4. Run the Mix servers:
	 ```
	$ python3 mix.py 3 9002
	 ```
	 ```
	$ python3 mix.py 2 9001
	 ```
	 ```
	$ python3 mix.py 1 9000
	 ```

5. Run the sending client:
   	```
	$ python3 sender.py 1
	 ```
