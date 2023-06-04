from server import Server

server = Server()

class Client:
    def __init__(self,username):
        self.username = username

    def recv(self):
        data = server.recv(self)

    def send(self, message):
        server.send(self, message)
        pass