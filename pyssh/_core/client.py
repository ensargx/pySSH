from socket import socket
from .message import Message
from .reader import Reader
from .hostkey import RSAKey

from pyssh.util import mpint, string, byte

from pyssh._core import packets, kex

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

        self.encryption = None
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

        kex_algorithm = kex.select_algorithm(self, kex_algorithms)
        kex_algorithm.protocol(self, client_kex_init=client_kex_init, *args, **kwargs)

        """
        Encryption keys MUST be computed as HASH, of a known value and K, as
        follows:
        o  Initial IV client to server: HASH(K || H || "A" || session_id)
            (Here K is encoded as mpint and "A" as byte and session_id as raw
            data.  "A" means the single character A, ASCII 65).

        o  Initial IV server to client: HASH(K || H || "B" || session_id)

        o  Encryption key client to server: HASH(K || H || "C" || session_id)

        o  Encryption key server to client: HASH(K || H || "D" || session_id)

        o  Integrity key client to server: HASH(K || H || "E" || session_id)

        o  Integrity key server to client: HASH(K || H || "F" || session_id)

        Key data MUST be taken from the beginning of the hash output.  As
        many bytes as needed are taken from the beginning of the hash value.
        If the key length needed is longer than the output of the HASH, the
        key is extended by computing HASH of the concatenation of K and H and
        the entire key so far, and appending the resulting bytes (as many as
        HASH generates) to the key.  This process is repeated until enough
        key material is available; the key is taken from the beginning of
        this value.  In other words:

            K1 = HASH(K || H || X || session_id)   (X is e.g., "A")
            K2 = HASH(K || H || K1)
            K3 = HASH(K || H || K1 || K2)
            ...
            key = K1 || K2 || K3 || ...

        This process will lose entropy if the amount of entropy in K is
        larger than the internal state size of HASH.
        """
        initial_iv_c2s = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"A" + self.kex.session_id)
        initial_iv_s2c = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"B" + self.kex.session_id)
        encryption_key_c2s = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"C" + self.kex.session_id)
        encryption_key_s2c = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"D" + self.kex.session_id)
        integrity_key_c2s = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"E" + self.kex.session_id)
        integrity_key_s2c = self.kex.hash(mpint(self.kex.K) + self.kex.H + b"F" + self.kex.session_id)

        # MAC ALGORITHM : HMAC-SHA1 (20 bytes)
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
