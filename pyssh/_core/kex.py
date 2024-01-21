import secrets

from .message import Message
from .reader import Reader
from pyssh.util import mpint, string, byte

### TODO: import client ...

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from Crypto.Hash import SHA1, SHA256
from Crypto.Hash.SHA1 import SHA1Hash
from Crypto.Hash.SHA256 import SHA256Hash

from typing import List, Protocol

#TODO: fix diffie hellmans

class KeyExchange(Protocol):
    @staticmethod
    def protocol(client, *args, **kwargs):
        """
        Key Exchange Protocol.

        This protocol will get K, H, and session id for the session.
        Also will add 'kex' attribute to client which has these variables.
        session id will be added to client as attribute as well
        """
        pass

    @property
    def K(self) -> int:
        """
        Shared Secret Key
        """
        ...

    @property
    def H(self) -> bytes:
        """
        Shared Hash
        """
        ...

    @property
    def session_id(self) -> bytes:
        """
        Session ID
        """
        ...

    @staticmethod
    def hash(data: bytes) -> bytes:
        """
        Hash Function
        """
        ...


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
    def protocol(client, client_kex_init: Reader, server_kex_init: Reader, *args, **kwargs):
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
            signature = client.host_key.sign(client.exchange_hash)

            reply = Message()
            reply.write_byte(31)
            reply.write_string(client.host_key.get_key())
            reply.write_mpint(dh_g1.f)
            reply.write_string(signature)

            client.send(reply)

    @property
    def K(self):
        """
        Shared Secret Key
        """
        return self.k

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
    def protocol(client, client_kex_init: Reader, server_kex_init: Reader, *args, **kwargs):
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
            signature = client.host_key.sign(client.exchange_hash)

            reply = Message()
            reply.write_byte(31)
            reply.write_string(client.host_key.get_key())
            reply.write_mpint(dh_g1.f)
            reply.write_string(signature)

            client.send(reply)

    @property
    def K(self):
        """
        Shared Secret Key
        """
        return self.k

class ECDHcurve25519SHA256:
    """Elliptic Curve Diffie-Hellman Curve25519 Key Exchange with SHA-256
    
    RFC7748#6.1
    """
    name = b'curve25519-sha256'

    def __init__(self, Q_C) -> None:
        if len(Q_C) != 32:
            raise ValueError("Invalid Q_C length")
        self.Q_C = Q_C

        # Convert Q_C to X25519PublicKey
        self.peer_public_key = x25519.X25519PublicKey.from_public_bytes(Q_C)

        # Generate 32 bytes of random data
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        
        # Convert private key to bytes
        self.private_bytes = self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Convert public key to bytes
        self.Q_S = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        self.shared_secret_K = self.private_key.exchange(self.peer_public_key)
        # self.shared_key_K = int.from_bytes(self.shared_key_K, byteorder='big')

    
    @staticmethod
    def protocol(client, client_kex_init: Reader, server_kex_init: Reader, *args, **kwargs):
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
            
            curve25519 = ECDHcurve25519SHA256(Q_C)
            setattr(client, 'kex', curve25519)

            concat = \
                string(client.client_banner.rstrip(b'\r\n')) + \
                string(client.server_banner.rstrip(b'\r\n')) + \
                string(client_kex_init.message) + \
                string(server_kex_init.message) + \
                string(client.host_key.get_key()) + \
                string(curve25519.Q_C) + \
                string(curve25519.Q_S) + \
                mpint(curve25519.shared_secret_K)

            hash_h = curve25519.hash(concat)
            curve25519.exchange_hash_H = hash_h
            curve25519.session_id = hash_h
            signature = client.host_key.sign(curve25519.exchange_hash_H)

            reply = Message()
            reply.write_byte(31)
            reply.write_string(client.host_key.get_key())
            reply.write_string(curve25519.Q_S)
            reply.write_string(signature)

            reply_new_keys = Message()
            reply_new_keys.write_byte(21)

            client.send(reply, reply_new_keys)

            new_keys = client.recv()
            
            if new_keys.read_byte() != 21:
                raise ValueError("Invalid message code")

    @property
    def K(self):
        """
        Shared Secret Key
        """
        # return self.shared_secret_K
        return int.from_bytes(self.shared_secret_K, byteorder='big')
    
    @property
    def H(self):
        """
        Shared Hash
        """
        return self.exchange_hash_H

    @staticmethod
    def hash(data: bytes):
        return SHA256.new(data).digest()


all_kex_algorithms = {
    b'diffie-hellman-group1-sha1': DHGroup1SHA1,
    b'diffie-hellman-group14-sha1': DHGroup14SHA1,
    b'curve25519-sha256': ECDHcurve25519SHA256
}

def select_algorithm(client, kex_algorithms: List[bytes]) -> KeyExchange:
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
