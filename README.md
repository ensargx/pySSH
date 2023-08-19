# pySSH
 Costumizable SSH Server with Python

Hey, I am trying to make an SSH server with Python. It will be costumizable and easy to use. I am still working on it. I will add more features soon. If you want to help me, you can fork this repository and make a pull request. I will be happy to see your contributions.

Feel free give me feedbacks and suggestions.

```python
from pyssh import pySSH
from pyssh import ClientBase

app = pySSH()


class Client(ClientBase):
    """
    Extra client class, you can add your own methods here.
    clients will be instances of this class.
    """
    pass


@app.event
def on_startup():
    print("Server is started")

@app.event
def on_establish(client: Client):
    print(client.username + " is established")

@app.event
def on_message(client: Client, data: bytes):
    print(data)

@app.event
def on_leave(client: Client):
    print(client.username + " is left")

@app.event
def on_shutdown():
    print("Server is closed")

if __name__ == '__main__':
    app.start()

```