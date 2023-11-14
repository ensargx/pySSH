import socket
import pyssh

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('localhost', 22))

    sock.listen(1)

    print('Listening at', sock.getsockname())
    client, addr = sock.accept()
    print('Connection from', addr)

    # Get data from client
    client_string = client.recv(1024)

    print(client_string)

    if not pyssh._core._conn_setup._protocol_version_exchange(client_string):
        print("Protocol version exchange failed.")

    print("Protocol version exchange succeeded.")

    # Send data to client
    server_banner = pyssh._core._packets._default_packets._get_pyssh_banner()
    client.send(server_banner)

    # Get data from client
    client_string = client.recv(1024)

    print(client_string)



if __name__ == '__main__':
    main()