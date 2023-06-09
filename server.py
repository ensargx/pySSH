import socket
import threading
import time
import establish
from client import Client

class Server:
    def __init__(self, host = 'localhost', port = 22, allowed_authentication_types = ['password','public_key']):
        self.clients = {}
        self.allowed_authentication_types = allowed_authentication_types
        self.host = host
        self.port = port

    def listen_process(self):
        """
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

    def start(self):
        listen_process = threading.Thread(target = self.listen_process)
        listen_process.start()

    def establish_connection(self, client_sock, address):

        # assume that the client is a valid ssh client and username is client1_username
        print("Connection from: " + str(address))
        client = Client("client1_username")
        self.clients[client] = client_sock

        # server will handle the connection with the server.ClientHandler class supplied by the user
        
        self.ClientHandler.establist(client)
        while True:
            data = client_sock.recv(1024)
            if not data:
                self.ClientHandler.leave(client)
                self.clients.pop(client)
                break
            self.ClientHandler.listen(client, data)

        

        '''
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
        '''

        

server = Server()
