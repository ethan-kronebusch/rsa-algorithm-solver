#!/usr/bin/python3

# Encrypted socket client example in python

# RSA encryption code adapted from https://stackoverflow.com/questions/30056762/rsa-encryption-and-decryption-in-python

import Crypto
from Crypto.PublicKey import RSA    #for key generation & management
from Crypto.Cipher import PKCS1_OAEP#for encryption & decryption
from Crypto import Random           #for random number generation
import socket	                    #for sockets
import json                         #for data parsing
import ast                          #for safely evaluating encrypted data
import sys                          #for exit

# create an INET(IPv4), STREAMing(TCP) socket
try:
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error:
    print ('Failed to create socket')
    sys.exit()

print ('Socket Created')

host = '127.0.0.1';   # the IP address of the server to connect
port = 3660;            # the port number of the application

# if you have the host name, the following lines convert the host
# name to the IP address
#
# try:
# 	remote_ip = socket.gethostbyname( host )
# 
# except socket.gaierror:
# 	# could not resolve
# 	print ('Hostname could not be resolved. Exiting')
# 	sys.exit()

# Generate public and private keys for secure data exchange
# Also store the public key seperately to exchange it with the server
rng = Random.new().read
key = RSA.generate(2048, rng)
publicKey = key.publickey()
decryptor = PKCS1_OAEP.new(key)

# Connect to remote server
s.connect((host , port))

print ('Socket Connected to IP' + host)

# Respond to server handshake
serverPubKey = RSA.importKey(s.recv(2048))
s.sendall(publicKey.exportKey())
serverEncryptor = PKCS1_OAEP.new(serverPubKey)
s.sendall(serverEncryptor.encrypt(b'Handshake succeeded with client'))
print(decryptor.decrypt(ast.literal_eval(str(s.recv(2048)))).decode())


print("\nWelcome to the Anagram Solver client!")
# Send some data to remote server
while True:
    message = input("Enter scrambled word: ")

    if " " in message:
       print("Please do not enter more than one word.")
       continue
    if len(message) > 2048:
        print("Your message is too long. Max message length is 2048 characters.")
        continue
    break

try:
	# encrypt the string and send it
	s.sendall(serverEncryptor.encrypt(message.encode()))
except socket.error:
	# Send failed
    print ('Send failed')
    sys.exit()

print ('Message has been sent successfully')

# recieve and decrypt message count from server
transactionsEncrypted = s.recv(2048)
transactions = int(decryptor.decrypt(ast.literal_eval(str(transactionsEncrypted))).decode())

anagramsJSON = ""

# recieve and concatenate each part of the message
for i in range(0, transactions):
    # receive data from server
    replyEncrypted = s.recv(2048)    # the maximum size of the data is 4096
    
    # acknowledge data recieved
    s.sendall(b'ok')

    # decrypt data
    reply = decryptor.decrypt(replyEncrypted)
    
    # decode the data to UTF-8 and add it to the final message string
    anagramsJSON += reply.decode()

# convert the full message back from JSON
anagrams = json.loads(anagramsJSON)
print("\n")

for i in reversed(range(1,len(message)+1)):
    print(f"Possible {i} letter words: " + str(anagrams[str(i)]))

# close the socket to free the resources used by the socket
s.close()
