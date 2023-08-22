from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

# Simulate Client and Server
class Client:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )

    def send_hello(self):
        return {
            "client_hello": {
                "supported_versions": ["TLSv1.2"],
                "cipher_suites": ["AES128-SHA256"],
            }
        }

    def receive_server_hello(self, server_hello):
        self.server_hello = server_hello

    def fetch_server_public_key(self):
        self.server_public_key = serialization.load_pem_public_key(
            self.server_hello["server_public_key"],
        )
        self.shared_secret = os.urandom(16)

    def send_key_exchange(self):
        encrypted_secret = self.server_public_key.encrypt(
            self.shared_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return {"encrypted_secret": encrypted_secret}

    def receive_session_established(self, session_established):
        self.session_established = session_established

class Server:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def send_server_hello(self):
        return {
            "server_hello": {
                "selected_version": "TLSv1.2",
                "selected_cipher_suite": "AES128-SHA256",
                "server_public_key": self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ),
            }
        }

    def receive_client_hello(self, client_hello):
        pass

    def receive_key_exchange(self, key_exchange):
        self.shared_secret = self.private_key.decrypt(
            key_exchange["encrypted_secret"],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def send_session_established(self):
        return {"session_established": True}

# Simulate TLS Handshake
client = Client()
server = Server()

client_hello = client.send_hello()
server.receive_client_hello(client_hello)

server_hello = server.send_server_hello()
client.receive_server_hello(server_hello)
client.fetch_server_public_key()  # Fetch the server's public key

key_exchange = client.send_key_exchange()
server.receive_key_exchange(key_exchange)

session_established = server.send_session_established()
client.receive_session_established(session_established)

print("TLS Handshake completed successfully!")
