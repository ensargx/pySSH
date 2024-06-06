from typing import List

from cryptography.hazmat.primitives.asymmetric import dsa, rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_ssh_private_key
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives import serialization 

# @todo: fix key import and signing 
# and maybe improve oop design 

from pyssh.util import mpint, string

from typing import Optional, Type
from abc import ABC, abstractmethod

class HostKey(ABC):
    name: bytes
    _hasher: Type[hashes.HashAlgorithm]

    @abstractmethod
    def __init__(self, key):
        ...

    @abstractmethod
    def get_key(self) -> bytes:
        ...

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        ...


class RSAKey(HostKey):
    name = b"ssh-rsa"
    _hasher = hashes.SHA1
    _padding = padding.PKCS1v15

    def __init__(self, rsa):
        self.private_key = rsa
        print(rsa)

    def sign(self, data: bytes) -> bytes:
        _hasher = self._hasher()
        _padding = self._padding()
        private_key = self.private_key
        signature = private_key.sign(data, _padding, _hasher)
        signature = string(self.name) + string(signature)
        return signature
    
    def get_key(self):
        public_numbers = self.private_key.public_key().public_numbers()
        return string(self.name) + mpint(public_numbers.e) + mpint(public_numbers.n)

class ECDSAKey(HostKey):
    name: bytes
    _hasher: Type[hashes.HashAlgorithm]
    private_key: ec.EllipticCurvePrivateKey

    def sign(self, data: bytes) -> bytes:
        ecdsa = ec.ECDSA(self._hasher())
        sig = self.get_private_key().sign(data, ecdsa)
        r, s = decode_dss_signature(sig)
        signature = string(self.name) + string(mpint(r) + mpint(s))
        return signature

    def get_private_key(self) -> ec.EllipticCurvePrivateKey:
        return self.private_key

class ECDSASHA2NISTP256(ECDSAKey):
    name = b"ecdsa-sha2-nistp256"
    _hasher = hashes.SHA256

    def __init__(self, key):
        self.private_key = key

    def get_key(self):
        public_key = self.private_key.public_key()
        Q_bytes = public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)
        return string(b"ecdsa-sha2-nistp256") + string(b"nistp256") + string(Q_bytes)

class ECDSASHA2NISTP384(HostKey):
    name = b"ecdsa-sha2-nistp384"
    _hasher = hashes.SHA384

    def __init__(self, key):
        self.private_key = key

    def get_key(self):
        public_numbers = self.private_key.public_key().public_numbers()
        return string(b"ecdsa-sha2-nistp384") + string(b"nistp384") + mpint(public_numbers.x) + mpint(public_numbers.y)

class ECDSASHA2NISTP521(HostKey):
    name = b"ecdsa-sha2-nistp521"
    _hasher = hashes.SHA512

    def __init__(self, key):
        self.private_key = key

    def get_key(self):
        public_numbers = self.private_key.public_key().public_numbers()
        return string(b"ecdsa-sha2-nistp521") + string(b"nistp521") + mpint(public_numbers.x) + mpint(public_numbers.y)

class ED25519:
    ...


supported_algorithms = {
    b"ssh-rsa": RSAKey,
    b"ecdsa-sha2-nistp256": ECDSASHA2NISTP256,
    b"ecdsa-sha2-nistp384": ECDSASHA2NISTP384,
    b"ecdsa-sha2-nistp521": ECDSASHA2NISTP521,
    # b"ssh-ed25519": ED25519,
}

def load_key(path: str, password: Optional[bytes] = None) -> HostKey:
    """
    Loads a hostkey from a file.

    :param path: The path to the file.
    :return: The hostkey.
    """
    print("Loading key:", path)
    try:
        key = load_ssh_private_key(open(path, "rb").read(), password)
    except ValueError:
        raise ValueError("Invalid key file.")

    if isinstance(key, rsa.RSAPrivateKey):
        return RSAKey(key)

    elif isinstance(key, ec.EllipticCurvePrivateKey):
        if key.curve.name == "secp256r1":
            return ECDSASHA2NISTP256(key)
        elif key.curve.name == "secp384r1":
            return ECDSASHA2NISTP384(key)
        elif key.curve.name == "secp521r1":
            return ECDSASHA2NISTP521(key)
        else:
            raise ValueError("Unsupported curve.")

    elif isinstance(key, dsa.DSAPrivateKey):
        raise ValueError("DSA is not supported.")

    raise ValueError("Unsupported key type.")

def generate_key(algorithm: bytes) -> HostKey:
    """
    Generates a new hostkey.

    :param algorithm: The algorithm to use.
    :return: The hostkey.
    """
    if algorithm == b"ssh-rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return RSAKey(key)
    elif algorithm == b"ecdsa-sha2-nistp256":
        key = ec.generate_private_key(ec.SECP256R1())
        return ECDSASHA2NISTP256(key)
    elif algorithm == b"ecdsa-sha2-nistp384":
        key = ec.generate_private_key(ec.SECP384R1())
        return ECDSASHA2NISTP384(key)
    elif algorithm == b"ecdsa-sha2-nistp521":
        key = ec.generate_private_key(ec.SECP521R1())
        return ECDSASHA2NISTP521(key)
    else:
        raise ValueError("Unsupported algorithm.")

def select_algorithm(algorithms: List[bytes]) -> bytes:
    """
    Selects the first algorithm in the list that is also in the server's list.

    :param algorithms: The algorithms to select from.
    :param server_algorithms: The server's algorithms.
    :return: The selected algorithm's name.
    """
    for algorithm in algorithms:
        if algorithm in supported_algorithms:
            return algorithm

    raise ValueError("No supported algorithms.")

