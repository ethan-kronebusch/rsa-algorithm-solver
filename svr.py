#!/usr/bin/python3

# RSA encryption code adapted from https://stackoverflow.com/questions/30056762/rsa-encryption-and-decryption-in-python

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random
import socket
import json
import math
import ast
import sys
import os
import re
import _thread as thread

#Function for finding anagrams of a word, given a wordlist and the input scramble.
def anagram_finder(scramble, wordlist, length):
    letterFreq = {}

    for letter in scramble:
        try:
            letterFreq[letter] += 1
        except KeyError:
            letterFreq[letter] = 1

    letters = ""
    for letter in list(letterFreq.keys()):
        letters += letter

    possWords = re.findall(f'(?:\\n|^)([{letters}]{{{length}}})(?:\\n|$)',wordlist,re.I)
    realWords = possWords.copy()
    
    for letter in letters:
        for word in possWords:
            if letterFreq[letter] - word.lower().count(letter) < 0:
                try:
                    realWords.remove(word)
                except:
                    continue
    return realWords

HOST = '127.0.0.1'	# the listening IP
PORT = 3660	            # the listening port

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print ('Socket created')

# Bind socket to local host and port
try:
	s.bind((HOST, PORT))
except (socket.error, msg):
	print ('Bind failed. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
	sys.exit()
	
print ('Socket bind complete')

# Start listening on socket, the size of queue is 10
s.listen(10)
print ('Socket now listening')

# Generate public and private keys for secure data exchange
# Also store the public key seperately to exchange it with the client
rng = Random.new().read
key = RSA.generate(2048, rng)
publicKey = key.publickey()
decryptor = PKCS1_OAEP.new(key)

# Function for handling connections. This will be used to create threads
def clientthread(conn):
    # Shake hands with client and exchange public keys
    conn.sendall(publicKey.exportKey())
    clientPubKey = RSA.importKey(conn.recv(2048))
    clientEncryptor = PKCS1_OAEP.new(clientPubKey)
    print(decryptor.decrypt(ast.literal_eval(str(conn.recv(2048)))).decode())
    conn.sendall(clientEncryptor.encrypt(b'Handshake succeeded with server'))

    # Attempt to load wordlist from file.
    try:
        wordfile = open("words.txt", "r")
        wordlist = wordfile.read()
    except FileNotFoundError:
        print("Wordlist not found! Please ensure that words.txt is in the same directory as this script and that Python has read privileges on it.")
        conn.close()
        return
    
	# Receiving from client
    dataEncrypted = conn.recv(2048)
    if not dataEncrypted: 
        conn.close()
        return
    
    # decrypt recieved data
    data = decryptor.decrypt(ast.literal_eval(str(dataEncrypted)))
    
    # get all anagrams in the client's input
    anagrams = {}
    for i in reversed(range(1,len(data.decode("utf-8"))+1)):
        anagrams[i] = anagram_finder(data.decode("utf-8"), wordlist, i)
        
    print(anagrams)
    # force flush for nohup
    sys.stdout.flush()
    
    # if data is greater than 190 bytes, it needs to be compressed
    reply = json.dumps(anagrams)
    
    transactions = math.ceil(len(reply)/190)
    conn.sendall(clientEncryptor.encrypt(str(transactions).encode()))
    
    if len(reply) > 190:
        #transmit each segment of the message
        for i in range(0,transactions):
            #transmit partial message
            conn.sendall(clientEncryptor.encrypt(reply[i*190:(i+1)*190].encode()))
            #wait for acknowledgement after each message
            conn.recv(5)
    else:
        conn.sendall(clientEncryptor.encrypt(reply.encode()))
    
    conn.close()

# now keep talking with the client
while True:
    # wait to accept a connection - blocking call
    # it will wait/hang until a connection request is coming
	conn, addr = s.accept()
	print ('\nConnected with ' + addr[0] + ':' + str(addr[1]))
	
	# start new thread takes 1st argument as a function name to be run,
    # second is the tuple of arguments to the function.
	thread.start_new_thread(clientthread, (conn,))

s.close()
