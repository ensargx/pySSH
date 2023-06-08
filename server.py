import socket
import threading
import time
import establish
from client import Client

class Server:
    def __init__(self, host = 'localhost', port = 22, allowed_authentication_types = ['password','public_key']):
        self.clients = {}
        self.queue = []
        self.allowed_authentication_types = allowed_authentication_types
        self.host = host
        self.port = port

    def listen_process(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        while True:
            print("Waiting for connection...")
            client, address = self.sock.accept()
            thread = threading.Thread(target = self.establish_connection, args = (client,address))
            thread.start()

        self.sock.close()

    def start(self):
        listen_process = threading.Thread(target = self.listen_process)
        listen_process.start()

    def accept(self):
        while True:
            if self.queue:
                client = self.queue.pop(0)
                client_obj = next(iter(client))
                socket_obj = client[client_obj]
                self.clients[client_obj] = socket_obj
                return client_obj

    def establish_connection(self, client, address):
        print("Connection from: " + str(address))
        #client_obj = Client("username")
        if not establish.check_version(client, address):
            """
            Client will not be accepted if it is not a valid ssh client or if it is not version 2.0
            """
            client.close()
            return
        kex = establish.key_exchange(client, address)


        """
        kex init 
        """
        time.sleep(20)
        client_obj = Client("username")
        print(client_obj)
        self.queue.append({client_obj: client})
        print(self.queue)
        

server = Server()
