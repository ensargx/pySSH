import os

from pyssh._core import kex, hostkey, mac 

class pySSH:
    def __init__(self, hostkey_path: str = './keys/'):
        """
        Initializes the SSH server.
        """
        self.hostkeys = {}
        self.hostkeys_path = hostkey_path
        self.auth_handler = {}

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

    def client(self, cls):
        """
        Decorator for adding a client to the server.
        """
        # Add send method for the client
        self.client_cls = cls
        return cls

    def auth(self, cls):
        """
        Decorator for adding auth methods to the server.

        The auth handler can be a class or a function.
        if the auth handler is a class, it can define auth names as methods.
        i.e.:

        class AuthHandler:
            @staticmethod 
            def none(username: bytes) -> bool:
                AuthHandler.check_name(username)
                return True

            @staticmethod
            def check_name(username: bytes):
                # Some db check ... 
                print("Username: ", username)

        The auth handler can also be a function.
        i.e.:

        def none(username: bytes) -> bool:
            print("Username: ", username)
            return True

        The auth handler must return a boolean value indicating if the authentication was successful or not.
        """
        type_ = getattr(getattr(cls, '__class__', None), '__name__', None)
        # if type_ is function:
        if type_ == 'function':
            self.auth_handler[cls.__name__] = cls
            return cls

        # if type_ is type (class):
        if type_ == 'type':
            auth_methods = [
                'none',
                'password',
                'publickey',
                'hostbased',
                'keyboard_interactive',
            ]
            for method in auth_methods:
                if hasattr(cls, method):
                    self.auth_handler[method] = getattr(cls, method)
            return cls

        raise ValueError("Invalid auth handler, must be a function or class.")

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
        server_mac_algorithms_c2s = [name for name in mac.supported_algorithms.keys()] 
        server_mac_algorithms_s2c = [name for name in mac.supported_algorithms.keys()] 

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
        while 1:
            client_sock, addr = sock.accept()
            print('Connection from', addr)
            client = Client(client_sock, server_algorithms, self.hostkeys)
            # setup complete, auth required
            if client.user_auth(self.auth_handler) is False:
                print("[DEBUG] User authentication failed.")
                client_sock.close()
                del client
                continue
            print("[DEBUG] User authenticated.")
            _send = client.get_send()
            _terminal = None
            _username = client.username
            _recv = client.get_recv()
            client_cls = self.client_cls(_send, _recv, _username, _terminal)
            print("DEBUG: client_cls: ", client_cls)
            print("DEBUG: client_cls.handler: ", client_cls.handler)
            client.handler(client_cls)
            # client loop
            import threading
            client_thread = threading.Thread(target=client.loop)
            client_thread.start()
        print("Server closed")
        
