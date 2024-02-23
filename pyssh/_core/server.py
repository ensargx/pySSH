import os

from pyssh._core import hostkey
from pyssh._core import kex

class pySSH:
    def __init__(self, hostkey_path: str = './keys/'):
        """
        Initializes the SSH server.
        """
        self.hostkeys = {}
        self.hostkeys_path = hostkey_path

    def load_hostkeys(self):
        """
        Loads the hostkeys from the hostkeys_path.
        """
        # Avaliable hostkeys
        hostkeys = [
            'ssh_host_rsa_key',
            'ssh_host_dsa_key',
            'ssh_host_ecdsa_key',
            'ssh_host_ed25519_key',
        ]
        # Loop over files in hostkeys_path
        for filename in os.listdir(self.hostkeys_path):
            """
            # Check if file is a hostkey
            if filename in hostkeys:
                # Add hostkey to list
                key = hostkey.load_key(self.hostkeys_path + filename)
                self.hostkeys[key.get_name()] = key
            """
            if filename in hostkeys:
                # Add hostkey to list
                key = hostkey.load_key(os.path.join(self.hostkeys_path, filename))
                print("DEBUG: Loaded hostkey: ", key.get_name())
                self.hostkeys[key.get_name()] = key
        # Check if there are any hostkeys
        print("DEBUG: Hostkeys: ", self.hostkeys)
        if len(self.hostkeys) == 0:
            raise ValueError("No hostkeys found.")


    def run(self, port: int = 22):
        """
        Runs the SSH server.
        """
        
        # Load hostkeys
        self.load_hostkeys()

        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('localhost', port))

        sock.listen(1)

        """
        TODO: server algorithms should be configurable s.t. the user can specify which algorithms to use.
              And server should create the algorithms based on the user's configuration and algorithms supported.
        """
            # Demo server algorithms
        server_kex_algorithms = [name for name in kex.supported_algorithms.keys()]
        server_host_key_algorithms = [
            b"ssh-rsa",
            # b"ecdsa-sha2-nistp256",
        ]
        server_encryption_algorithms_c2s = [
            b"aes128-ctr",
        ]
        server_encryption_algorithms_s2c = [
            b"aes128-ctr",
        ]
        server_mac_algorithms_c2s = [
            b"hmac-sha1",
        ]
        server_mac_algorithms_s2c = [
            b"hmac-sha1",
        ]
        server_compression_algorithms_c2s = [
            b"none",
        ]
        server_compression_algorithms_s2c = [
            b"none",
        ]
        server_languages_c2s = [
            b"",
        ]
        server_languages_s2c = [
            b"",
        ]

        server_algorithms = {
            'kex_algorithms': server_kex_algorithms,
            'host_key_algorithms': server_host_key_algorithms,
            'encryption_algorithms_c2s': server_encryption_algorithms_c2s,
            'encryption_algorithms_s2c': server_encryption_algorithms_s2c,
            'mac_algorithms_c2s': server_mac_algorithms_c2s,
            'mac_algorithms_s2c': server_mac_algorithms_s2c,
            'compression_algorithms_c2s': server_compression_algorithms_c2s,
            'compression_algorithms_s2c': server_compression_algorithms_s2c,
            'languages_c2s': server_languages_c2s,
            'languages_s2c': server_languages_s2c,
        }

        from pyssh._core.client import Client
        client_sock, addr = sock.accept()
        print('Connection from', addr)
        client = Client(client_sock, server_algorithms, self.hostkeys)        

