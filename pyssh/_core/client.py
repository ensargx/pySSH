from socket import socket
from .message import Message
from .reader import Reader
from .hostkey import RSAKey

from pyssh.util import mpint, string, byte

from pyssh._core.kex import select_algorithm

from pyssh._core import packets

class Client:
    def __init__(
        self,
        client_sock: socket,
        *args, 
        **kwargs
    ):
        self.client_sock = client_sock
        self.server_banner = packets.pyssh_banner

        self.encryption = None
        self.mac = None
        self.compression = None

        return self.setup_connection(*args, **kwargs)
    
    def recv(self, *args, **kwargs) -> Reader:
        data = self.client_sock.recv(4096)

        if self.compression is not None:
            data = self.compression.decompress(data)

        if self.mac is not None:
            self.mac.verify(data)

        if self.encryption is not None:
            data = self.encryption.decrypt(data)

        data = packets.ssh_packet(data)
        return Reader(data.payload)
    
    def send(self, *messages: Message, **kwargs):
        """
        data = message.payload

        if self.encryption is not None:
            data = self.encryption.encrypt(data)

        if self.mac is not None:
            self.mac.sign(data)

        if self.compression is not None:
            data = self.compression.compress(data)

        packet = ssh_packet._create_packet(data)
        self.client_sock.send(bytes(packet))
        """

        raw_data = b''
        # For each message in messages:
        for message in messages:
            data = message.payload

            if self.encryption is not None:
                data = self.encryption.encrypt(data, **kwargs)

            if self.mac is not None:
                self.mac.sign(data, **kwargs)

            if self.compression is not None:
                data = self.compression.compress(data, **kwargs)

            packet = packets.ssh_packet.create_packet(data, **kwargs)
            raw_data += bytes(packet)

        self.client_sock.send(raw_data)


    def setup_connection(self, *args, **kwargs):
        self.client_sock.send(self.server_banner)
        
        client_banner = self.client_sock.recv(4096)
        client_banner = packets.protocol_version_exchange(client_banner)
        if not client_banner:
            raise NotImplementedError("Protocol version exchange failed.")
        self.client_banner = client_banner

        server_kex_init = packets.key_exchange_init()
        server_kex_init = packets.ssh_packet.create_packet(server_kex_init)
        self.client_sock.send(bytes(server_kex_init))
        server_kex_init = Reader(server_kex_init.payload)

        return self.key_exchange_init(server_kex_init=server_kex_init, client_banner=client_banner, *args, **kwargs)

    def key_exchange_init(self, *args, **kwargs):
        client_kex_init = self.client_sock.recv(4096)
        client_kex_init = packets.ssh_packet(client_kex_init)
        client_kex_init = Reader(client_kex_init.payload)

        message_code = client_kex_init.read_byte()

        # İF MESSAGE CODE == 20
        cookie = client_kex_init.read_bytes(16)
        kex_algorithms = client_kex_init.read_name_list()
        server_host_key_algorithms = client_kex_init.read_name_list()
        encryption_algorithms_client_to_server = client_kex_init.read_name_list()
        encryption_algorithms_server_to_client = client_kex_init.read_name_list()
        mac_algorithms_client_to_server = client_kex_init.read_name_list()
        mac_algorithms_server_to_client = client_kex_init.read_name_list()
        compression_algorithms_client_to_server = client_kex_init.read_name_list()
        compression_algorithms_server_to_client = client_kex_init.read_name_list()
        languages_client_to_server = client_kex_init.read_name_list()
        languages_server_to_client = client_kex_init.read_name_list()
        first_kex_packet_follows = client_kex_init.read_boolean()
        reserved = client_kex_init.read_uint32()

        # TODO : IMPLEMENT HOST KEY STUFF...
        print("HOST KEY STUFF: IMPLEMENT ME")
        from pyssh._core.hostkey import RSAKey
        host_key = RSAKey("/home/ensargok/keys/id_rsa.pub", "/home/ensargok/keys/id_rsa")
        self.host_key = host_key

        kex_algorithm = select_algorithm(self, kex_algorithms)
        kex_algorithm.protocol(self, client_kex_init=client_kex_init, *args, **kwargs)


        return self.loop(*args, **kwargs)
    
    def loop(self, *args, **kwargs):
        
        """
        Client loop.
        """
        pass
