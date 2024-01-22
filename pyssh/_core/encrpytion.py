from typing import List, Protocol

from Crypto.Cipher import AES
from Crypto.Util import Counter

class Encryption(Protocol):
    
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


class AES128CTR:
    def __init__(self, initial_iv: bytes, encryption_key: bytes):
        self.ctr = Counter.new(128, initial_value=int.from_bytes(initial_iv, "big"))
        self.cipher = AES.new(encryption_key, AES.MODE_CTR, counter=self.ctr)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.cipher.encrypt(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.cipher.decrypt(ciphertext)



supperted_algorithms = {
        b"aes128-ctr": AES128CTR,
        }

def select_encryption_algorithm(algorithms_client: List[bytes], algorithms_server: List[bytes]) -> Encryption:
    """
    Selects an encryption algorithm to use for the communication.
    """ 

    # Select the first algorithm that is supported by both client and server.
    for algorithm_client in algorithms_client:
        if algorithm_client in algorithms_server:
            return globals()[supperted_algorithms[algorithm_client].__name__]

    raise Exception("No supported encryption algorithm found.")
