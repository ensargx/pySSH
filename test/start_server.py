from pyssh import pySSH
import os

hostkey_path = os.path.join(os.path.expanduser('~'), 'keys')

app = pySSH(
    hostkey_path = hostkey_path
)

@app.auth
class Auth:
    @staticmethod
    def none(username: bytes):
        Auth.check_name(username)
        return False

    @staticmethod
    def password(username: bytes, password: bytes):
        print("Checking password, username:", username, "password:", password)
        if password == b"password":
            return True
        return False

    @staticmethod
    def check_name(username: bytes):
        print("Checking username:", username)

@app.client
class Client:
    _all_clients = []
    def __init__(self, send, recv, username, terminal):
        self.send = send
        self.terminal = terminal
        self.username = username
        self.recv = recv
        self._all_clients.append(self)
        self._line = b''
        print("Client connected:", username)
        print("All clients:", self._all_clients)
        print("Terminal:", terminal)
        print("Send:", send)

    def handler(self, data: bytes):
        print(data)
        if data == b'\r':
            if self._line == b'exit':
                self.send(b'Goodbye!\r\n')
                self.terminal.close()
                self._all_clients.remove(self)
                return
            for client in self._all_clients:
                if client != self:
                    client.new_message(self._line, self.username)
            # send clear_line + username + b': '
            self.send(b'\x1b[2K\r' + self.username + b': ' + self._line + b'\r\n' + self.username + b': ')
            self._line = b''
        elif data == b'\x7f':
            self._line = self._line[:-1]
            # send clear_line + username + b': ' + line
            self.send(b'\x1b[2K\r' + self.username + b': ' + self._line)
        else:
            self._line += data
            self.send(data)

    def new_message(self, message: bytes, author: bytes):
        # send clear_line + author + b': ' + message + newline + \ + username + line
        self.send(b'\x1b[2K\r' + author + b': ' + message + b'\r\n' + self.username + b': ' + self._line)


print("Starting Server")
app.run(port=2222)
