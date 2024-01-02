from socket import socket
from .message import Message
from .reader import Reader
from .hostkey import RSAKey

from ._util import mpint, string, byte

from . import kex

from pyssh._core._core_classes import _core_packet
from pyssh._core import _packets

class Client:
    def __init__(self, client_sock: socket, *args, **kwargs):
        self.client_sock = client_sock
        self.server_banner = _packets._get_pyssh_banner()

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

        data = _core_packet(data)
        return Reader(data.payload)
    
    def send(self, message: Message, *args, **kwargs):
        data = message.payload

        if self.encryption is not None:
            data = self.encryption.encrypt(data)

        if self.mac is not None:
            self.mac.sign(data)

        if self.compression is not None:
            data = self.compression.compress(data)

        packet = _core_packet._create_packet(data)
        self.client_sock.send(bytes(packet))

    def select_kex_algorithm(self, kex_algorithms: list):
        print("NOT FULLY IMPLEMENTED: CLİENT.SELECT_KEX_ALGORITHM")
        for algorithm in kex_algorithms:
            if algorithm == b"diffie-hellman-group14-sha1":
                return kex.DHGroup14SHA1
            elif algorithm == b"diffie-hellman-group1-sha1":
                return kex.DHGroup1SHA1
            else:
                raise NotImplementedError(f"{algorithm} is not implemented.")

    def setup_connection(self, *args, **kwargs):
        self.client_sock.send(self.server_banner)
        
        client_banner = self.client_sock.recv(4096)
        client_banner = _packets._conn_setup._protocol_version_exchange(client_banner)
        if not client_banner:
            raise NotImplementedError("Protocol version exchange failed.")
        self.client_banner = client_banner

        server_kex_init = _packets._get_key_exchange_init()
        server_kex_init = _core_packet._create_packet(server_kex_init)
        self.client_sock.send(bytes(server_kex_init))
        server_kex_init = Reader(server_kex_init.payload)

        return self.key_exchange(server_kex_init=server_kex_init, client_banner=client_banner, *args, **kwargs)


    def key_exchange(self, *args, **kwargs):
        client_kex_init = self.client_sock.recv(4096)
        client_kex_init = _core_packet(client_kex_init)
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

        selected_kex_algorithm = self.select_kex_algorithm(kex_algorithms)
        self.kex_algorithm = selected_kex_algorithm

        # TODO : IMPLEMENT HOST KEY STUFF...
        from pyssh._core.hostkey import RSAKey
        host_key = RSAKey("/home/ensargok/keys/id_rsa.pub", "/home/ensargok/keys/id_rsa.pem")
        self.host_key = host_key

        return self.diffie_hellman(client_kex_init=client_kex_init, *args, **kwargs)

    # if kex message code is 30:
    def client_dh_g_1_14_sha1(self, message: Reader, *args, **kwargs):
        e = message.read_mpint()
        dh_g1 = self.kex_algorithm(e)

        client_kex_init: Reader = kwargs.get("client_kex_init")
        server_kex_init: Reader = kwargs.get("server_kex_init")

        concat = \
            string(self.client_banner.rstrip(b'\r\n')) + \
            string(self.server_banner.rstrip(b'\r\n')) + \
            string(client_kex_init.message) + \
            string(server_kex_init.message) + \
            string(self.host_key.get_key()) + \
            mpint(dh_g1.e) + \
            mpint(dh_g1.f) + \
            mpint(dh_g1.k)

        hash_h = dh_g1.hash(concat)
        self.exchange_hash = hash_h.digest()
        signature = self.host_key.sign_sha1(self.exchange_hash)

        reply = Message()
        reply.write_byte(31)
        reply.write_string(self.host_key.get_key())
        reply.write_mpint(dh_g1.f)
        reply.write_string(signature)

        self.send(reply)


    # if kex message code is 34:
    def client_dh_group_exchange(self, message: Reader, *args, **kwargs):
        raise NotImplementedError("Now i am gonna implement this")


    def diffie_hellman(self, *args, **kwargs):
        client_dh_init = self.recv()
        
        message_code = client_dh_init.read_byte()

        if message_code == 30:
            return self.client_dh_g_1_14_sha1(client_dh_init, *args, **kwargs)
        elif message_code == 32:
            raise NotImplementedError("omg not implemented")
        elif message_code == 34:
            return self.client_dh_group_exchange(client_dh_init, *args, **kwargs)

