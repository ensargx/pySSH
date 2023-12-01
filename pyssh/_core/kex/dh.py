import secrets
from abc import ABC, abstractmethod
from ..hash import Hash
from dataclasses import dataclass


class DiffieHellman(ABC):
    name: bytes
    hash_name: bytes
    g: int
    p: int
    q: int
    hash_func: Hash

    def __init__(self):
        pass
    
    @abstractmethod
    def hash(data: bytes):
        pass

@dataclass
class DHGroup1SHA1:
    """Diffie-Hellman Group 1 Key Exchange with SHA-1"""
    name = b'diffie-hellman-group1-sha1'
    hash_name = b'sha1'
    g = 2
    p = int(
        'FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1'
        '29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD'
        'EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245'
        'E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED'
        'EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381'
        'FFFFFFFF FFFFFFFF'.replace(' ', ''), 16)
    q = (p - 1) // 2
    hash_func = Hash.SHA1

    def __init__(self):
        raise NotImplementedError("ALTTAKİ CLASS'DAN BAK BURAYA KOPYALA")
        self.x = secrets.randbelow(self.q - 1) + 1
        self.e = pow(self.g, self.x, self.p)
        self.f = None
        self.k = None
        self.h = None
    
    def generate_y(self):
        self.y = secrets.randbelow(DHGroup1SHA1.q)
        return self.y
    
    def generate_f(self):
        self.f = pow(DHGroup1SHA1.g, self.y, DHGroup1SHA1.p)
        return self.f

    def compute_k(self):
        self.k = pow(self.e, self.y, self.p)
        return self.k

    def generate_h(self, data: bytes):
        self.h = self.hash_func(data)
        return self.h

class DHGroup14SHA1(DiffieHellman):
    """Diffie-Hellman Group 14 Key Exchange with SHA-1"""
    name = b'diffie-hellman-group14-sha1'
    p = int(
        'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'
        '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'
        'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'
        'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'
        'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'
        'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'
        '83655D23DCA3AD961C62F356208552BB9ED529077096966D'
        '670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B'
        'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9'
        'DE2BCBF6955817183995497CEA956AE515D2261898FA0510'
        '15728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
    g = 2
    q = (p - 1) // 2
    hash_func = Hash.SHA1

    def __init__(self, e: int):
        self.e = e
        self.y = secrets.randbelow(DHGroup1SHA1.q - 1) + 1
        self.f = pow(DHGroup1SHA1.g, self.y, DHGroup1SHA1.p)
        self.k = pow(self.e, self.y, DHGroup1SHA1.p)

    @staticmethod
    def hash(data: bytes):
        return DHGroup14SHA1.hash_func(data)
