# pySSH
 Costumizable SSH Server with Python

Hey, I am trying to make an SSH server with Python. It will be costumizable and easy to use. I am still working on it. I will add more features soon. If you want to help me, you can fork this repository and make a pull request. I will be happy to see your contributions.

Feel free give me feedbacks and suggestions.

## Install
You can easily install pyssh with 

```bash
pip install pyssh@git+https://github.com/ensargx/pyssh
```

Or, you can clone the repository and build it on your machine

```bash
git clone https://github.com/ensargx/pySSH.git
cd pySSH
pip install .
```

## Example
This is and example server for chatting, people can connect and chat with each other.

### Client 1

```bash
~/dev/pySSH (main*) » ssh ensar@localhost -o HostKeyAlgorithms=ssh-rsa -p 2222
Welcome to the chat room, ensar!
user: hey
ensar: what's up
ensar:
```

### Client 2 

```bash
~/dev/pySSH (main*) » ssh user@localhost -o HostKeyAlgorithms=ssh-rsa -p 2222
Welcome to the chat room, user!
user: hey
ensar: what's up
user:
```

### Implementation

```python
from pyssh import pySSH
import os

hostkey_path = os.path.join(os.path.expanduser('~'), 'keys')

app = pySSH(
    hostkey_path = hostkey_path
)

@app.client
class Client:
    all_clients = []
    def __init__(self, send, recv, username, terminal):
        self.send = send
        self.recv = recv
        self.terminal = terminal
        self.all_clients.append(self)
        self.line = b''

        # username is bold
        self.username = b'\x1b[1m' + username + b'\x1b[0m'

    def wellcome_message(self):
        return b"Welcome to the chat room, " + self.username + b"!\r\n" + self.username + b": "

    def send_message(self, message):
        # clear_line + message + newline + username + prompt 
        self.send(b'\x1b[2K\r' + message + b'\r\n' + self.username + b': ' + self.line)

    def handler(self, data):
        if data == b'\r': # enter
            # handle sending message to all clients
            if self.line == b'':
                return
            print(self.username.decode(), ': ', self.line.decode(), sep='')
            for client in self.all_clients:
                if client != self:
                    client.send_message(self.username + b': ' + self.line)
            self.send(b'\r\n' + self.username + b': ')
            self.line = b''
        elif data == b'\x03': # Ctrl+C
            # handle quitting
            self.send(b'Do you really want to quit? (y/n)')
            answer = self.recv()
            if answer == b'y':
                self.quit(b"Goodbye!")
            else:
                self.send(b'Continue...\r\n' + self.username + b':' + self.line)
        elif data == b'\x7f': # backspace
            # handle backspace
            if self.line == b'':
                return
            self.line = self.line[:-1]
            self.send(b'\b \b')
        elif data == b'\x1b': # escape
            # handle escape
            ...
        elif data == b'\t': # tab
            # handle tab (convert to 4 spaces)
            self.line += b'    '
            self.send(b'    ')
        elif data == b'\x04': # Ctrl+D
            # handle Ctrl+D
            self.send(b'Goodbye!')
            self.quit()
        else:
            # handle normal character
            self.line += data
            self.send(data)

    def quit(self, message=b''):
        self.send(b'\r\n' + message + b'\r\n')



if __name__ == '__main__':
    app.run(port=2222)
```

