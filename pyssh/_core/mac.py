
import hmac

from typing import Protocol


class MAC(Protocol):
    def __init__(self, iv):
        ...

    def verify(self, data, mac) -> bool:
        ...
    
    def sign(self, data) -> bytes:
        ...
    
    def parse(self, data) -> bytes:
        ...

class MACNone(MAC):
    mac_len = 0
    def __init__(self, iv = None):
        return

    def verify(self, data, mac):
        return True
    
    def sign(self, data):
        return b""
    
    def parse(self, data):
        return data, b""

class HMACSHA1(MAC):
    mac_len = 20
    def __init__(self, iv):
        if len(iv) > 20:
            iv = iv[:20]
        elif len(iv) < 20:
            raise ValueError("IV must be at least 20 bytes long.")
        self.mac = hmac.new(iv, digestmod='sha1')

    def verify(self, data, mac):
        self.mac.update(data)
        return self.mac.digest() == mac

    def sign(self, data):
        self.mac.update(data)
        return self.mac.digest()
    
    def parse(self, data):
        return data[:-20], data[-20:]