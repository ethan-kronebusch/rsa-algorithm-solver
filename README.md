To run this program, you have to execute "pip install pycryptodome".

Encryption/Decryption algorithms:

-I'm using RSA for data encryption, with a public key exchange (handshake) when the server connects to the client. All data after the handshake is encrypted & padded according to the PKCS#1 RSA standard before transmission. The server never sees the client's private key, and the client never sees the server's private key.