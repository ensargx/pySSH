import socket
import threading
import re
import multiprocessing

class Server:
    def __init__(self, host = 'localhost', port = 22, allowed_authentication_types = ['password','public_key']):
        self.clients = {}
        self.queue = []
        self.allowed_authentication_types = allowed_authentication_types
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))

    def listen_process(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            threading.Thread(target = self.establish_connection, args = (client,address)).start()

        self.sock.close()

    def listen(self):
        listen_process = multiprocessing.Process(target = self.listen_process)
        listen_process.start()

    def accept(self):
        while True:
            if self.queue:
                client_obj = self.queue.pop(0)
                return client_obj

    def establish_connection(self, client,address):
        print("Connection from: " + str(address))
        client_obj = Client(server = self, username = "kemal", listening = False)
        self.queue.append(client_obj)
        print(self.queue)
        
        

class Client:
    def __init__(self,server,username,listening = False):
        self.listening = listening
        self.username = username

    def listen(self):
        while self.listening:
            pass