from .hostkey import HostKey
from pyssh.util import mpint, string, byte

from Crypto.PublicKey import RSA

from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA1, SHA256

# class RSAKey(HostKey):
class RSAKey:
    def __init__(self, public_key_path: str, private_key_path: str):
        self.public_key_path = public_key_path
        self.private_key_path = private_key_path

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

    def sign_sha1(self, data: bytes) -> bytes:
        signature = self._pkcs1_15.sign(SHA1.new(data))
        signature = string("ssh-rsa") + string(signature)
        return signature
    
    def sign_sha256(self, data: bytes) -> bytes:
        signature = self._pkcs1_15.sign(SHA256.new(data))
        signature = string("ssh-rsa") + string(signature)
        return signature