from typing import List, Protocol

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.modes import CTR
from cryptography.hazmat.primitives.ciphers.algorithms import AES 

class Encryption(Protocol):
    cipher_block_size: int
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
    cipher_block_size = 8
    def __init__(self, encryption_key: bytes = b"", initial_iv: bytes = b""):
        pass

    def encrypt(self, plaintext: bytes) -> bytes:
        return plaintext

    def decrypt(self, ciphertext: bytes) -> bytes:
        return ciphertext

class AES128CTR:
    cipher_block_size = 16
    def __init__(self, encryption_key: bytes, initial_iv: bytes):
        print("initial_iv: ", initial_iv, "len: ", len(initial_iv))
        self.ctr = CTR(initial_iv[:16])
        self.cipher = Cipher(AES(encryption_key[:16]), self.ctr, None)

        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.encryptor.update(plaintext)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.decryptor.update(ciphertext)


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
