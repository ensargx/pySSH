import secrets

from .message import Message
from .reader import Reader
from .client import Client
from ._util import mpint, string, byte

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from Crypto.Hash import SHA1, SHA256
from Crypto.Hash.SHA1 import SHA1Hash
from Crypto.Hash.SHA256 import SHA256Hash

from typing import List, Protocol

class KeyExchange(Protocol):

    @staticmethod
    def protocol(client: Client, *args, **kwargs):
        """
        Key Exchange Protocol
        """
        pass

class DHGroup1SHA1:
    """Diffie-Hellman Group 1 Key Exchange with SHA-1"""
    name = b'diffie-hellman-group1-sha1'
    p = 179769313486231590770839156793787453197860296048756011706444423684197180216158519368947833795864925541502180565485980503646440548199239100050792877003355816639229553136239076508735759914822574862575007425302077447712589550957937778424442426617334727629299387668709205606050270810842907692932019128194467627007
    g = 2
    q = 89884656743115795385419578396893726598930148024378005853222211842098590108079259684473916897932462770751090282742990251823220274099619550025396438501677908319614776568119538254367879957411287431287503712651038723856294775478968889212221213308667363814649693834354602803025135405421453846466009564097233813503

    def __init__(self, e: int):
        self.e = e
        self.y = secrets.randbelow(self.q - 1) + 1
        self.f = pow(self.g, self.y, self.p)
        self.k = pow(self.e, self.y, self.p)

    @staticmethod
    def hash(data: bytes) -> SHA1Hash:
        return SHA1.new(data)
    
    @staticmethod
    def protocol(client: Client, client_kex_init: Reader, server_kex_init: Reader, *args, **kwargs):
        """
        Diffie-Hellman Group 1 Key Exchange with SHA-1 Protocol
        """
        packet: Reader = client.recv()

        message_code = packet.read_byte()
        if message_code == 30:
            e = packet.read_mpint()
            dh_g1 = DHGroup1SHA1(e)
            
            concat = \
                string(client.client_banner.rstrip(b'\r\n')) + \
                string(client.server_banner.rstrip(b'\r\n')) + \
                string(client_kex_init.message) + \
                string(server_kex_init.message) + \
                string(client.host_key.get_key()) + \
                mpint(dh_g1.e) + \
                mpint(dh_g1.f) + \
                mpint(dh_g1.k)
            
            hash_h = dh_g1.hash(concat)
            client.exchange_hash = hash_h.digest()
            signature = client.host_key.sign_sha1(client.exchange_hash)

            reply = Message()
            reply.write_byte(31)
            reply.write_string(client.host_key.get_key())
            reply.write_mpint(dh_g1.f)
            reply.write_string(signature)

            client.send(reply)

class DHGroup14SHA1:
    """Diffie-Hellman Group 14 Key Exchange with SHA-1"""
    name = b'diffie-hellman-group14-sha1'
    p = 32317006071311007300338913926423828248817941241140239112842009751400741706634354222619689417363569347117901737909704191754605873209195028853758986185622153212175412514901774520270235796078236248884246189477587641105928646099411723245426622522193230540919037680524235519125679715870117001058055877651038861847280257976054903569732561526167081339361799541336476559160368317896729073178384589680639671900977202194168647225871031411336429319536193471636533209717077448227988588565369208645296636077250268955505928362751121174096972998068410554359584866583291642136218231078990999448652468262416972035911852507045361090559
    g = 2
    q = 16158503035655503650169456963211914124408970620570119556421004875700370853317177111309844708681784673558950868954852095877302936604597514426879493092811076606087706257450887260135117898039118124442123094738793820552964323049705861622713311261096615270459518840262117759562839857935058500529027938825519430923640128988027451784866280763083540669680899770668238279580184158948364536589192294840319835950488601097084323612935515705668214659768096735818266604858538724113994294282684604322648318038625134477752964181375560587048486499034205277179792433291645821068109115539495499724326234131208486017955926253522680545279

    def __init__(self, e: int):
        self.e = e
        self.y = secrets.randbelow(self.q - 1) + 1
        self.f = pow(self.g, self.y, self.p)
        self.k = pow(self.e, self.y, self.p)

    @staticmethod
    def hash(data: bytes) -> SHA1Hash:
        return SHA1.new(data)

    @staticmethod
    def protocol(client: Client, client_kex_init: Reader, server_kex_init: Reader, *args, **kwargs):
        """
        Diffie-Hellman Group 14 Key Exchange with SHA-1 Protocol
        """
        packet: Reader = client.recv()

        message_code = packet.read_byte()
        if message_code == 30:
            e = packet.read_mpint()
            dh_g1 = DHGroup14SHA1(e)
            
            concat = \
                string(client.client_banner.rstrip(b'\r\n')) + \
                string(client.server_banner.rstrip(b'\r\n')) + \
                string(client_kex_init.message) + \
                string(server_kex_init.message) + \
                string(client.host_key.get_key()) + \
                mpint(dh_g1.e) + \
                mpint(dh_g1.f) + \
                mpint(dh_g1.k)
            
            hash_h = dh_g1.hash(concat)
            client.exchange_hash = hash_h.digest()
            signature = client.host_key.sign_sha1(client.exchange_hash)

            reply = Message()
            reply.write_byte(31)
            reply.write_string(client.host_key.get_key())
            reply.write_mpint(dh_g1.f)
            reply.write_string(signature)

            client.send(reply)

class ECDHcurve25519SHA256:
    """Elliptic Curve Diffie-Hellman Curve25519 Key Exchange with SHA-256
    
    RFC7748#6.1
    
    """
    def __init__(self) -> None:
        self.private_key = None
        self.private_bytes = None
        self.public_key = None
        self.public_bytes = None
        self.shared_key = None
        
    
    @staticmethod
    def protocol(client: Client, client_kex_init: Reader, server_kex_init: Reader, *args, **kwargs):
        """

        RFC8731#3.1
        Curve25519/448 outputs a binary string X, which is the 32- or 56-byte
        point obtained by scalar multiplication of the other side's public 
        key and the local private key scalar. The 32 or 56 bytes of X are 
        converted into K by interpreting the octets as an unsigned fixed-
        length integer encoded in network byte order.
        """
        packet: Reader = client.recv()

        message_code = packet.read_byte()

        # ECDH Curve25519 Key Exchange with SHA-256
        if message_code == 30:
            Q_C = packet.read_string()

            if len(Q_C) != 32:
                raise ValueError("Invalid Q_C length")
            
            # Generate 32 bytes of random data
            private_key = x25519.X25519PrivateKey.generate()
            public_key = private_key.public_key()

            # Convert private key to bytes
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )

            # Convert public key to bytes
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            # Convert Q_C to X25519PublicKey
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(Q_C)
            
            shared_key = private_key.exchange(peer_public_key)

            concat = \
                string(client.client_banner.rstrip(b'\r\n')) + \
                string(client.server_banner.rstrip(b'\r\n')) + \
                string(client_kex_init.message) + \
                string(server_kex_init.message) + \
                string(client.host_key.get_key()) + \
                string(public_bytes) + \
                string(Q_C) + \
                string(shared_key)
            
            hash_h = ECDHcurve25519SHA256.hash(concat)
            client.exchange_hash = hash_h.digest()
            signature = client.host_key.sign_sha256(client.exchange_hash)

            reply = Message()
            reply.write_byte(31)
            reply.write_string(client.host_key.get_key())
            reply.write_string(public_bytes)
            reply.write_string(signature)


            ## TEST VECTOR
            private_a_bytes = 0x77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
            private_a_bytes = private_a_bytes.to_bytes(32, byteorder='big')
            # generate public key from private key
            private_a = x25519.X25519PrivateKey.from_private_bytes(private_a_bytes)
            public_a = private_a.public_key()
            public_a_bytes = public_a.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            # convert public key to bytes
            a_pub = 0x8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
            a_pub = a_pub.to_bytes(32, byteorder='big')
            assert public_a_bytes == a_pub

            private_b_bytes = 0x5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb
            # generate public key from private key
            private_b_bytes = private_b_bytes.to_bytes(32, byteorder='big')
            private_b = x25519.X25519PrivateKey.from_private_bytes(private_b_bytes)
            public_b = private_b.public_key()
            public_b_bytes = public_b.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            # convert public key to bytes
            b_pub = 0xde9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f
            b_pub = b_pub.to_bytes(32, byteorder='big')
            assert public_b_bytes == b_pub

            # generate shared key from private key and public key
            shared_key = private_a.exchange(public_b)
            # convert shared key to bytes
            shared_key_bytes = 0x4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
            shared_key_bytes = shared_key_bytes.to_bytes(32, byteorder='big')
            assert shared_key_bytes == shared_key
            

            

            
    @staticmethod
    def hash(data: bytes) -> SHA256Hash:
        return SHA256.new(data)


all_kex_algorithms = {
    b'diffie-hellman-group1-sha1': DHGroup1SHA1,
    b'diffie-hellman-group14-sha1': DHGroup14SHA1,
    b'ecdh-sha2-nistp256': ECDHcurve25519SHA256
}

def select_algorithm(client: Client, kex_algorithms: List[bytes]) -> KeyExchange:
    """
    Selects the most secure algorithm from the given list of algorithms.

    :param kex_algorithms: name-list of key exchange algorithms.
    :type kex_algorithms: bytes
    :param client: Client object.
    :type client: Client
    :return: Selected algorithm class.
    :rtype: class
    """

    for algorithm in kex_algorithms:
        if algorithm in all_kex_algorithms:
            return all_kex_algorithms[algorithm]
    
    raise NotImplementedError(f"No algortithms to use, not implemented.")
