from socket import socket
from .message import Message
from .reader import Reader

from pyssh.util import mpint, uint32
from pyssh._core import hostkey

from pyssh._core import packets, kex, encryption

from typing import Dict, List

class Client:
    def __init__(
        self,
        client_sock: socket,
        server_algorithms: Dict[str, List[bytes]],
        server_hostkeys: Dict[bytes, hostkey.HostKey],
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
        self.hostkey: hostkey.HostKey
        self._sequence_number_c2s = 0
        self._sequence_number_s2c = 0

        return self.setup_connection(server_algorithms, server_hostkeys, *args, **kwargs)
    
    def recv(self) -> Reader:
        data = self.client_sock.recv(4096)
        self._sequence_number_c2s += 1

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


    def setup_connection(self, server_algorithms, server_hostkeys):
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

        client_kex_init = self.client_sock.recv(4096)
        client_kex_init = packets.ssh_packet(client_kex_init)
        client_kex_init = Reader(client_kex_init.payload)

        message_code = client_kex_init.read_byte()
        assert message_code == 20

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

        kex_algorithm = kex.select_algorithm(kex_algorithms, server_algorithms["kex_algorithms"])
        if kex_algorithm is None:
            raise Exception("No supported key exchange algorithm found.") # TODO: Implement exception

        host_key_algorithm = hostkey.select_algorithm(server_host_key_algorithms)
        if host_key_algorithm is None:
            raise Exception("No supported host key algorithm found.") # TODO: Implement exception
        self.hostkey = server_hostkeys[host_key_algorithm]

        # Set encryption algorithms, TODO: Fix this, server algorithm should be used
        encryption_s2c = encryption.select_algorithm(encryption_algorithms_server_to_client, server_algorithms["encryption_algorithms_s2c"])
        if encryption_s2c is None:
            raise Exception("No supported encryption algorithm found.")
        encryption_c2s = encryption.select_algorithm(encryption_algorithms_client_to_server, server_algorithms["encryption_algorithms_c2s"])
        if encryption_c2s is None:
            raise Exception("No supported encryption algorithm found.")


        self.kex = kex_algorithm.protocol(self, client_kex_init=client_kex_init, server_kex_init=server_kex_init)

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

        data = self.encryption_c2s.decrypt(encrypted_data)

        # Control the mac
        # Mac algorithm is hmac-sha1
        import hmac
        import sys

        sequence_number = uint32(3)

        hmac_c2s = hmac.new(integrity_key_c2s[:20], digestmod='sha1')
        hmac_c2s.update(sequence_number + data)
        hmac_c2s = hmac_c2s.digest()

        assert len(hmac_c2s) == 20, "HMAC length is not 20"
        assert len(mac_sent) == 20, "MAC length is not 20"

        if hmac_c2s != mac_sent:
            print("MAC verification failed, received:", mac_sent, "expected:", hmac_c2s)

        print("END OF THE TEST!")
        print("NOW, AUTH WILL START")

        packet_len = int.from_bytes(data[:4], "big")
        padding_len = data[4]
        payload = data[5:packet_len]
        random_padding = data[packet_len:packet_len+padding_len]
        random_padding = random_padding

        reader = Reader(payload)
        byte_service_req = reader.read_byte()
        service_req = reader.read_string()

        print(byte_service_req)
        print(service_req)

        # return self.loop(*args, **kwargs)
    
    def loop(self, *args, **kwargs):
        
        """
        Client loop.
        """
        pass
