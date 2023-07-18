import socket
import threading
import time
import asyncio
import pySSH.establish as establish
import pySSH.exceptions as exceptions
from pySSH.client import Client as Client

class Server:
    def __init__(self, host = 'localhost', port = 22, allowed_authentication_types = ['password','public_key']):
        self.clients = {}
        self.allowed_authentication_types = allowed_authentication_types
        self.host = host
        self.port = port
        self.startup_func = lambda: None
        self.establish_func = lambda: None

    def listen_process(self):
        """
        # TODO
        This function is called in a thread and listens for incoming connections
        After the connection is made, a new thread is created to establish the ssh connection and handle the connection
        After the process is finished, the socket is closed, and the thread is closed
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        while True:
            print("Waiting for connection...")
            client, address = self.sock.accept()
            thread = threading.Thread(target = self.establish_connection, args = (client,address))
            thread.start()

        self.sock.close()

    def close_conn(self, client: Client, exception: exceptions.SSHException = None):
        self.clients[client].send(b'Bye')
        self.clients[client].close()

    """
    user can use @app.on_startup to add a function to be called when the server is started, it can be null
    """
    def on_startup(self, func):
        if not callable(func):
            raise TypeError("on_startup function must be callable")
        self.startup_func = func

    def on_establish(self, func):
        if not callable(func):
            raise TypeError("on_establish function must be callable")
        self.establish_func = func

    def start(self):
        self.startup_func()
        listen_process = threading.Thread(target = self.listen_process)
        listen_process.start()

    def establish_connection(self, client_sock, address):
        """
        This function is called in a thread and establishes the ssh connection
        After the connection is established, the server will call the on_establish function
        After the connection is closed, the server will call the on_leave function
        """

        # Check the SSH Version
        establish.check_version(client_sock, address)

        # Check the SSH Key Exchange
        establish.key_exchange_init(client_sock, address)


        # assume that the client is a valid ssh client and username is client1_username
        client_obj = Client(self, "client1_username")
        self.clients[client_obj] = client_sock
        self.establish_func()
        return


        # assume that the client is a valid ssh client and username is client1_username
        print("Connection from: " + str(address))
        client = Client(self, "client1_username")
        self.clients[client] = client_sock

        # server will handle the connection with the server.ClientHandler class supplied by the user
        
        # if this function throws exception, close the connection with the exception
        establish.check_version(client, address)


        self.ClientHandler.establist(client)
        while True:
            data = client_sock.recv(1024)
            if not data:
                self.ClientHandler.leave(client)
                self.clients.pop(client)
                break
            self.ClientHandler.listen(client, data)

        


        #client_obj = Client("username")
        if not establish.check_version(client, address):
            """
            Client will not be accepted if it is not a valid ssh client or if it is not version 2.0
            """
            client.close()
            return
        kex = establish.key_exchange_init(client, address)


        """
        kex init 
        """
        time.sleep(20)
        client_obj = Client("username")
        print(client_obj)
        self.queue.append({client_obj: client})
        print(self.queue)
