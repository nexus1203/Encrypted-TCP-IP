import base64
import socket
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class Server:

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
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(1)

    def generate_key(self, username, password):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                         length=32,
                         salt=username,
                         iterations=100000,
                         backend=default_backend())
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def listen_for_message(self, client_socket):
        data = client_socket.recv(1024)
        if not data:
            return None
        decrypted_data = self.cipher_suite.decrypt(data)
        return decrypted_data.decode('utf-8')

    def send_message(self, client_socket, message):
        encrypted_message = self.cipher_suite.encrypt(message.encode('utf-8'))
        client_socket.send(encrypted_message)

    def close(self):
        self.server_socket.close()
        print("Server shutdown")

    def handle_client(self, client_socket, client_address):
        while True:
            message = self.listen_for_message(client_socket)
            if message is None:
                break
            print(f"Server received: {message} from {client_address}")
            self.send_message(client_socket, f"Echo: {message}")


if __name__ == '__main__':
    username = b'username'  # replace with your username
    password = b'password'  # replace with your password
    server = Server(username=username, password=password)
    try:
        while True:
            client_socket, client_address = server.server_socket.accept()
            print(f"Accepted connection from {client_address}")
            server.handle_client(client_socket, client_address)
            print(f"Connection closed from {client_address}")
    except KeyboardInterrupt:
        server.close()
