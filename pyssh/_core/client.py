from socket import socket
from .message import Message
from .reader import Reader
from .hostkey import RSAKey

from pyssh.util import mpint, string, byte

from pyssh._core import packets, kex, encryption

from Crypto.Util import Counter
from Crypto.Cipher import AES

class Client:
    def __init__(
        self,
        client_sock: socket,
        *args, 
        **kwargs
    ):
        self.client_sock = client_sock
        self.server_banner = packets.pyssh_banner

        self.encryption_c2s = None
        self.encryption_s2c = None
        self.mac = None
        self.compression = None
        self.kex: kex.KeyExchange
        self.session_id = None
        self.client_banner = None

        return self.setup_connection(*args, **kwargs)
    
    def recv(self, *args, **kwargs) -> Reader:
        data = self.client_sock.recv(4096)

        if self.compression is not None:
            data = self.compression.decompress(data)

        if self.encryption_c2s is not None:
            data = self.encryption_c2s.decrypt(data)

        if self.mac is not None:
            self.mac.verify(data)

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

            if self.encryption_s2c is not None:
                data = self.encryption_s2c.encrypt(data, **kwargs)

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
        # pyright thinks reserved is unused, and it is, and gives warning, so we use it
        reserved = reserved
        # cookie is unused too, so we use it
        cookie = cookie

        # TODO : IMPLEMENT HOST KEY STUFF...
        print("HOST KEY STUFF: IMPLEMENT ME")
        from pyssh._core.hostkey import RSAKey
        host_key = RSAKey("/home/ensargok/keys/id_rsa.pub", "/home/ensargok/keys/id_rsa")
        self.host_key = host_key

        kex_algorithm = kex.select_algorithm(self, kex_algorithms)
        if kex_algorithm is None:
            raise Exception("No supported key exchange algorithm found.") # TODO: Implement exception

        # Set encryption algorithms, TODO: Fix this, server algorithm should be used
        encryption_s2c = encryption.select_algorithm(encryption_algorithms_client_to_server, encryption_algorithms_server_to_client)
        if encryption_s2c is None:
            raise Exception("No supported encryption algorithm found.")
        encryption_c2s = encryption.select_algorithm(encryption_algorithms_client_to_server, encryption_algorithms_server_to_client)
        if encryption_c2s is None:
            raise Exception("No supported encryption algorithm found.")


        kex_algorithm.protocol(self, client_kex_init=client_kex_init, *args, **kwargs)

        initial_iv_c2s = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"A" + self.kex.session_id)
        initial_iv_s2c = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"B" + self.kex.session_id)
        encryption_key_c2s = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"C" + self.kex.session_id)
        encryption_key_s2c = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"D" + self.kex.session_id)
        integrity_key_c2s = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"E" + self.kex.session_id)
        integrity_key_s2c = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"F" + self.kex.session_id)

        # Encryption is now enabled
        self.encryption_c2s = encryption_c2s(encryption_key_c2s, initial_iv_c2s)
        self.encryption_s2c = encryption_s2c(encryption_key_s2c, initial_iv_s2c)

        raw_data = self.client_sock.recv(4096)
        encrypted_data = raw_data[:-20]
        mac_sent = raw_data[-20:]

        ctr = Counter.new(128, initial_value=int.from_bytes(initial_iv_c2s[:16], "big"))
        cipher = AES.new(encryption_key_c2s[:16], AES.MODE_CTR, counter=ctr)

        data = cipher.decrypt(encrypted_data)

        packet_len = int.from_bytes(data[:4], "big")
        padding_len = data[4]
        payload = data[5:packet_len]
        random_padding = data[packet_len:packet_len+padding_len]

        reader = Reader(payload)
        byte_service_req = reader.read_byte()
        service_req = reader.read_string()

        print(byte_service_req)
        print(service_req)

        # controll mac
        from Crypto.Hash import HMAC, SHA1
        mac = HMAC.new(integrity_key_c2s[:20], digestmod=SHA1)
        mac.update(data)
        mac = mac.digest()

        print(data)


        return self.loop(*args, **kwargs)
    
    def loop(self, *args, **kwargs):
        
        """
        Client loop.
        """
        pass
