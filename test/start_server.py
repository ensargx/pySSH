import socket
import pyssh

from pyssh._core.client import Client

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 22))

    sock.listen(1)

    print('Listening at', sock.getsockname())
    client_sock, addr = sock.accept()
    print('Connection from', addr)
    client = Client(client_sock)

    print()


if __name__ == '__main__':
    main()
