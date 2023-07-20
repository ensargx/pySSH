import socket
import threading
import time
import asyncio
import pySSH.establish as establish
import pySSH.exceptions as exceptions
from pySSH.client import ClientBase as ClientBase

class Server:
    def __init__(self, host = 'localhost', port = 22, allowed_authentication_types = ['password','public_key']):
        self.clients = {}
        self.allowed_authentication_types = allowed_authentication_types
        self.host = host
        self.port = port
        self.listen_process_thread = None

        """
        Events
        on_startup: called when the server is started
        on_establish: called when a client is established
        on_message: called when a client sends a message
        on_leave: called when a client leaves
        on_shutdown: called when the server is closed
        """

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
        while self.is_running:
            print("Waiting for connection...")
            client, address = self.sock.accept()
            thread = threading.Thread(target = self.establish_connection, args = (client,address))
            thread.start()

        self.sock.close()

    def close_conn(self, client, exception: exceptions.SSHException = None):
        self.clients[client].send(b'Bye')
        self.clients[client].close()

    def Client(self, client_class):
        """
        Decarator for client subclasse, client_class must inherit from ClientBase
        server will create objects of the client_class and pass it to the user,
        user can use ClientBase methods and attributes in the client_class.
        
        
        Example:
        from psSSH import pySSH, ClientBase

        app = pySSH()

        @app.Client
        class MyClient(ClientBase):
            def __init__(self):
                super().__init__(self)
                self.name = super().username
        """
        if not issubclass(client_class, ClientBase):
            raise TypeError("Client class must inherit from ClientBase")
        self.ClientClass = client_class
        print(self.ClientClass)
        return client_class

    def event(self, func: callable):
        """
        Decorator for event handlers
        Example:

        @app.event
        def on_startup():
            print("Server started")

        @app.event
        def on_message(client, data):
            print("Message from client: " + data.decode())
            
        Events:
        on_startup: called when the server is started, arguments: none
        on_establish: called when a client is established, arguments: client
        on_message: called when a client sends a message, arguments: client, data
        on_leave: called when a client leaves, arguments: client
        on_shutdown: called when the server is closed, arguments: none
        """
        if not callable(func):
            raise TypeError("on_startup function must be callable")
  
        setattr(self, func.__name__, func)
        return func

    def start(self):
        self.on_startup()
        self.is_running = True
        listen_process = threading.Thread(target = self.listen_process)
        listen_process.start()
        self.listen_process_thread = listen_process
        return

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
        client_obj = self.ClientClass()
        print(self.ClientClass)
        # initialize the clientbase object 
        
        client_obj.super().password = "Test1"
        self.clients[client_obj] = client_sock
        self.on_establish(client_obj)
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

    def shutdown(self):
        print("0000")
        self.on_shutdown()
        self.is_running = False
        # close all the connections
        for client in self.clients:
            self.clients[client].close()
        # close the listening_thread
        print("1 the server...")
        self.listen_process_thread.join()
        print("2 the server...")
        self.sock.close()
        return


    # EVENT HANDLERS

    def on_startup(self):
        return
    
    def on_establish(self):
        return
    
    def on_leave(self):
        return
    
    def on_close(self):
        return
    
    def on_message(self, client, message):
        return