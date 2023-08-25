from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

import hashlib
import hmac

import os

def prf(secret, label, seed, length):
    prf_output = b""
    while len(prf_output) < length:
        hmac_digest = hmac.new(secret, seed + label, hashlib.sha256).digest()
        prf_output += hmac_digest
        seed = hmac_digest
    
    return prf_output[:length]

def derive_session_keys(master_secret, client_random, server_random):
    key_length = 16 # AES-128 key length in bytes
    iv_length = 16 # AES-128 block size (IV size) in bytes
    key_block_length = key_length * 2 + iv_length * 2  # Total length of keys and IVs

    # Use the PRF to generate pseudorandom bytes
    key_block = prf(master_secret, b"key expansion", client_random + server_random, key_block_length)

    # Split the key_block into individual keys and IVs
    client_write_key = key_block[:key_length]
    server_write_key = key_block[key_length:key_length * 2]
    client_write_iv = key_block[key_length * 2:key_length * 2 + iv_length]
    server_write_iv = key_block[key_length * 2 + iv_length:]

    return client_write_key, server_write_key, client_write_iv, server_write_iv

class Server:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.server_random_num = os.urandom(32)
        self.client_random_num = 0

        self.master_secret = 0
        self.write_key = 0
        self.write_IV = 0

        self.client_write_key = 0
        self.client_write_IV = 0

        self.highest_version = "TLSv1.2"
        self.selected_cipher_suite = "TLS_RSA_WITH_AES_128_CBC_SHA256"
    
    def receive_client_hello(self, client_hello):
        version = client_hello["client_hello"]["supported_version"]
        self.client_random_num = client_hello["client_hello"]["randomNum"]
        cipher_suite = client_hello["client_hello"]["cipher_suite"]

        if version != self.highest_version:
            print("Unsupported versions, Handshake was unsuccesful")
            return False
        if cipher_suite != self.selected_cipher_suite:
            print("Unsupported cipher suites, Handshake was unsuccesful")
            return False
        
        return version, cipher_suite
    
    def send_server_hello(self, highest_version, selected_cipher_suite):
        return {
            "server_hello": {
                "selected_version": highest_version,
                "randomNum": self.server_random_num,
                "sessionID": 0x0000000000000000,
                "selected_cipher_suite": selected_cipher_suite,
            }
        }
    
    def recieve_client_key_exchance(self, encrypted_pre_master_secret):
        self.pre_master_secret = self.private_key.decrypt(
            encrypted_pre_master_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )



class Client:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.client_random_num = os.urandom(32) 
        self.server_random_num = 0

        self.master_secret = 0
        self.write_key = 0
        self.write_IV = 0

        self.server_write_key = 0
        self.server_write_IV = 0

        self.established_version = ""
        self.established_cipher_suite = ""

    def send_hello(self):
        return {
            "client_hello": {
                "supported_version": "TLSv1.2",
                "randomNum": self.client_random_num,
                "sessionID": 0x0000000000000000,
                "cipher_suite": "TLS_RSA_WITH_AES_128_CBC_SHA256",
            }
        }
    
    def recieve_server_hello(self, server_hello):
        self.established_version = server_hello["server_hello"]["selected_version"]
        self.server_random_num = server_hello["server_hello"]["randomNum"]
        self.established_cipher_suite = server_hello["server_hello"]["selected_cipher_suite"]

    def client_key_exchange(self, server_public_key):
        self.pre_master_secret = os.urandom(48)
        encrypted_pre_master_secret = server_public_key.encrypt(self.pre_master_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return encrypted_pre_master_secret

server = Server()
client = Client()

client_send_hello = client.send_hello()
print("1. Client Hello sent succesfully")

version, cipher_suite = server.receive_client_hello(client_send_hello)
print("2. Server Hello recieved succesfully")

server_send_hello = server.send_server_hello(version, cipher_suite)
print("3. Server Hello sent succesfully")

client.recieve_server_hello(server_send_hello)
print("4. Server Hello recieved succesfully")

server_certificate = server.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
print("5. Server sent certificate succesfully")

encrypted_pre_master_secret = client.client_key_exchange(server.public_key)
server.recieve_client_key_exchance(encrypted_pre_master_secret)
print("6. Client sent encrypted pre master secret successfully")

# Both client and server generate the master secret
client.master_secret = prf(client.pre_master_secret, b"master secret", client.client_random_num + server.server_random_num, 48)
server.master_secret = prf(server.pre_master_secret, b"master secret", client.client_random_num + server.server_random_num, 48)

if client.master_secret != server.master_secret:
    print("ERROR: Master secrets do not match")
print("7. Master secrets succesfully generated")

client_write_key, server_write_key, client_write_iv, server_write_iv = derive_session_keys(client.master_secret, client.client_random_num, server.server_random_num)

# Save the keys into the respective servers
client.write_key = server.client_write_key = client_write_key
client.server_write_key = server.write_key = server_write_key

if client.write_key != server.client_write_key and client.server_write_key != server.write_key:
    print("ERROR: Keys were not generated or stored correctly.")
print("8.1 Client & Server keys generated and stored correctly")

# Save the Ivs into the respective servers
client.write_IV = server.client_write_IV = client_write_iv
client.server_write_IV = server.write_IV = server_write_iv

if client.write_IV != server.client_write_IV and client.server_write_IV != server.write_IV:
    print("ERROR: IVs were not generated or stored correctly.")
print("8.2 Client & Server IVs generated and stored correctly")
