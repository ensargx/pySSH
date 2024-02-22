
import hmac

from typing import Protocol, List, Tuple


class MAC(Protocol):
    def __init__(self, iv):
        ...

    def verify(self, data, mac) -> bool:
        ...
    
    def sign(self, data) -> bytes:
        ...
    
    def parse(self, data) -> Tuple[bytes, bytes]:
        ...

    @property
    def mac_len(self) -> int:
        ...

class MACNone(MAC):
    def __init__(self, iv = None):
        return

    def verify(self, data, mac):
        return True
    
    def sign(self, data):
        return b""
    
    def parse(self, data):
        return data, b""

    @property
    def mac_len(self):
        return 0

class HMACSHA1(MAC):
    def __init__(self, iv):
        if len(iv) > 20:
            iv = iv[:20]
        elif len(iv) < 20:
            raise ValueError("IV must be at least 20 bytes long.")
        self._iv = iv
        self.mac = hmac.new(iv, digestmod='sha1')

    def verify(self, data, mac): # TODO: wtf happening
        return hmac.new(self._iv, data, digestmod='sha1').digest() == mac
        self.mac.update(data)
        return self.mac.digest() == mac #TODO: use mac.compare_digest / hexdigest

    def sign(self, data):
        return hmac.new(self._iv, data, digestmod='sha1').digest()
        self.mac.update(data)
        return self.mac.digest()
    
    def parse(self, data):
        return data[:-20], data[-20:]
    
    @property
    def mac_len(self):  # TODO: maybe change mac_len name to digest_size
        return self.mac.digest_size 
    
supported_algorithms = {
        b"hmac-sha1": HMACSHA1,
    }

def select_algorithm(algorithms: List[bytes], server_algorithms: List[bytes]):
    """
    Selects an encryption algorithm to use for the communication.

    :param algorithms_client: List of algorithms supported by the client.
    """ 

    # Select the first algorithm that is supported by both client and server.
    for algorithm in algorithms:
        if algorithm in server_algorithms:
            return supported_algorithms[algorithm]
