from typing import List

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, ec
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

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

    def sign(self, data: bytes) -> bytes:
        _hasher = self._hasher()
        _padding = self._padding()
        private_key = self.private_key
        signature = private_key.sign(data, _padding, _hasher)
        signature = string(self.name) + string(signature)
        return signature


class RSAKey(HostKey):
    name = b"ssh-rsa"
    _hasher = hashes.SHA1
    _padding = padding.PKCS1v15

    def __init__(self, rsa):
        self.private_key = rsa
        print(rsa)
    
    def get_key(self):
        public_numbers = self.private_key.public_key().public_numbers()
        return string(self.name) + mpint(public_numbers.e) + mpint(public_numbers.n)

class ECDSASHA2NISTP256(HostKey):
    name = b"ecdsa-sha2-nistp256"
    _hasher = hashes.SHA256

    def _padding(self):
        return None

    def __init__(self, key):
        self.private_key = key

    def get_key(self):
        public_numbers = self.private_key.public_key().public_numbers()
        return string(b"ecdsa-sha2-nistp256") + string(b"nistp256") + mpint(public_numbers.x) + mpint(public_numbers.y)

    def sign(self, data: bytes) -> bytes:
        print("signing")
        _hasher = self._hasher()
        private_key = self.private_key
        signature = private_key.sign(data, ec.ECDSA(_hasher))
        signature = string(self.name) + string(signature)
        return signature


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
    # b"ecdsa-sha2-nistp256": ECDSASHA2NISTP256,
    # b"ecdsa-sha2-nistp384": ECDSASHA2NISTP384,
    # b"ecdsa-sha2-nistp521": ECDSASHA2NISTP521,
    # b"ssh-ed25519": ED25519,
}

def load_key(path: str, password: Optional[bytes] = None) -> HostKey:
    """
    Loads a hostkey from a file.

    :param path: The path to the file.
    :return: The hostkey.
    """
    print(path) 
    with open(path, "rb") as file:
        private_key = serialization.load_pem_private_key(
            file.read(),
            password=password
        )

    if isinstance(private_key, rsa.RSAPrivateKey):
        return RSAKey(private_key)

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return ECDSASHA2NISTP256(private_key)

    raise ValueError("Hostkey not supported:", path)

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

