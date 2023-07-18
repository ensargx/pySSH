from pySSH.exceptions import WrongVersionException

class Client:
    def __init__(self, server, username: str):
        self.username = username
        self.server = server

    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if isinstance(exc_val, WrongVersionException):
            self.server.close_conn(self, exc_type, exc_val, exc_tb)

    def recv(self):
        data = self.server.recv(self)

    def send(self, message):
        self.server.send(self, message)
        pass