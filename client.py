import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import socket


class Client:

    def __init__(self,
                 host='localhost',
                 port=12345,
                 username=None,
                 password=None):
        self.host = host
        self.port = port
        self.key = self.generate_key(
            username,
            password) if username and password else Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))

    def generate_key(self, username, password):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=32,
                         salt=username,
                         iterations=100000,
                         backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def listen_for_message(self):
        data = self.client_socket.recv(1024)
        if not data:
            return None
        decrypted_data = self.cipher_suite.decrypt(data)
        print(f"Received: {decrypted_data.decode('utf-8')}")
        return decrypted_data.decode('utf-8')

    def send_message(self, message):
        encrypted_message = self.cipher_suite.encrypt(message.encode('utf-8'))
        self.client_socket.send(encrypted_message)

    def close(self):
        self.client_socket.close()
        print("Client shutdown")


if __name__ == '__main__':
    from time import sleep

    username = b'username'  # replace with your username
    password = b'password'  # replace with your password
    client = Client(username=username, password=password)

    try:
        for i in range(10):
            client.send_message("Hello, Server!")
            message = client.listen_for_message()
            if message:
                print(f"Client received: {message}")
            sleep(1)
    except KeyboardInterrupt:
        client.close()
