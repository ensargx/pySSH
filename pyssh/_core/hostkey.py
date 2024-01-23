from abc import ABC, abstractmethod
from typing import List

from Crypto.PublicKey import RSA, DSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1, SHA256

from pyssh.util import mpint, string

from typing import Protocol

class HostKey(Protocol):
    name: bytes

    def __init__(self, key_path: str):
        ...

    def get_name(self) -> bytes:
        ...

    def get_key(self) -> bytes:
        ...

    def sign(self, data: bytes) -> bytes:
        ...


class RSAKey(HostKey):
    name = b"ssh-rsa"

    def __init__(self, key_path: str):
        self.private_key_path = key_path
        self.public_key_path = key_path + ".pub"

        self.public_key = RSA.importKey(open(self.public_key_path, "rb").read())
        self.private_key = RSA.importKey(open(self.private_key_path, "rb").read())
        self._pkcs1_15 = pkcs1_15.new(self.private_key)

        self.n = self.public_key.n
        self.e = self.public_key.e
        self.d = self.private_key.d
        self.p = self.private_key.p
        self.q = self.private_key.q
        self.u = self.private_key.u

    def get_name(self):
        return b"ssh-rsa"
    
    def get_key(self):
        return string("ssh-rsa") + mpint(self.public_key.e) + mpint(self.public_key.n)

    def sign(self, data: bytes) -> bytes:
        signature = self._pkcs1_15.sign(SHA1.new(data))
        signature = string("ssh-rsa") + string(signature)
        return signature

    # TODO: Delete this
    def sign_sha1(self, data: bytes) -> bytes:
        signature = self._pkcs1_15.sign(SHA1.new(data))
        signature = string("ssh-rsa") + string(signature)
        return signature
    
    def sign_sha256(self, data: bytes) -> bytes:
        signature = self._pkcs1_15.sign(SHA256.new(data))
        signature = string("ssh-rsa") + string(signature)
        return signature


class DSAKey(HostKey):
    name = b"ssh-dss"

    def __init__(self, key_path: str):
        self.private_key_path = key_path
        self.public_key_path = key_path + ".pub"

        self.public_key = DSA.importKey(open(self.public_key_path, "rb").read())
        self.private_key = DSA.importKey(open(self.private_key_path, "rb").read())
        self._pkcs1_15 = pkcs1_15.new(self.private_key)

        self.p = self.public_key.p
        self.q = self.public_key.q
        self.g = self.public_key.g
        self.y = self.public_key.y
        self.x = self.private_key.x

    def get_name(self):
        return b"ssh-dss"
    
    def get_key(self):
        return string("ssh-dss") + mpint(self.public_key.p) + mpint(self.public_key.q) + mpint(self.public_key.g) + mpint(self.public_key.y)

    def sign(self, data: bytes) -> bytes:
        signature = self._pkcs1_15.sign(SHA1.new(data))
        signature = string("ssh-dss") + string(signature)
        return signature


class ECDSA(HostKey):
    ...


class ED25519(HostKey):
    ...


supported_algorithms = {
    b"ssh-rsa": RSAKey,
}

def load_key(path: str):
    """
    Loads a hostkey from a file.

    :param path: The path to the file.
    :return: The hostkey.
    """
    if path.endswith(".pub"):
        path = path[:-4]

    for key_type in supported_algorithms.values():
        try:
            return key_type(path)
        except ValueError:
            continue

    raise ValueError("Invalid hostkey.")

def select_algorithm(algorithms: List[bytes], server_algorithms: List[bytes]) -> bytes:
    """
    Selects the first algorithm in the list that is also in the server's list.

    :param algorithms: The algorithms to select from.
    :param server_algorithms: The server's algorithms.
    :return: The selected algorithm's name.
    """
    for algorithm in algorithms:
        if algorithm in server_algorithms:
            return algorithm
