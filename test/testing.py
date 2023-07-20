import sys

sys.path.append("../")
sys.path.append("../../")

#from client import Client, server

from pySSH import pySSH
from pySSH import ClientBase as ClientBase

app = pySSH()

@app.Client
class Client(ClientBase):
    """
    Example:

    from psSSH import pySSH, ClientBase

    app = pySSH()

    @app.Client
    class MyClient(ClientBase):
        def __init__(self):
            super().__init__(self)
            self.name = super().username
                
    """
    pass


@app.event
def on_startup():
    print("Server is started")

@app.event
def on_establish(client: Client):
    print(client.username + " is established")

@app.event
def on_message(client: Client, data):
    print(data)

@app.event
def on_leave(client: Client):
    print(client.username + " is left")

@app.event
def on_shutdown():
    print("Server is closed")

if __name__ == '__main__':
    app.start()
    while True:
        cmd = input(">>> ")
        if cmd == "exit":
            app.shutdown()
            break
    print("Server is closed")
    sys.exit(0)