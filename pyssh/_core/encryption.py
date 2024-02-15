from typing import List, Protocol

from Crypto.Cipher import AES
from Crypto.Util import Counter

class Encryption(Protocol):
    
    def __init__(self, encryption_key: bytes, initial_iv: bytes):
        """
        Initializes the encryption algorithm.
        """
        ...

    def encrypt(self, plaintext) -> bytes:
        """
        Encrypts the plaintext and returns the ciphertext.
        """
        ...

    def decrypt(self, ciphertext) -> bytes:
        """
        Decrypts the ciphertext and returns the plaintext.
        """
        ...

class EncryptionNone(Encryption):
    def __init__(self, encryption_key: bytes = b"", initial_iv: bytes = b""):
        pass

    def encrypt(self, plaintext: bytes) -> bytes:
        return plaintext

    def decrypt(self, ciphertext: bytes) -> bytes:
        return ciphertext

class AES128CTR:
    def __init__(self, encryption_key: bytes, initial_iv: bytes):
        self.ctr = Counter.new(128, initial_value=int.from_bytes(initial_iv[:16], "big"))
        self.cipher = AES.new(encryption_key[:16], AES.MODE_CTR, counter=self.ctr)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.cipher.decrypt(ciphertext)


supperted_algorithms = {
        b"aes128-ctr": AES128CTR,
    }

def select_algorithm(algorithms: List[bytes], server_algorithms: List[bytes]):
    """
    Selects an encryption algorithm to use for the communication.

    :param algorithms_client: List of algorithms supported by the client.
    """ 

    # Select the first algorithm that is supported by both client and server.
    for algorithm in algorithms:
        if algorithm in server_algorithms:
            return supperted_algorithms[algorithm]
