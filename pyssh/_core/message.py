from pyssh.util import mpint, string, uint32, uint64, name_list, byte

from dataclasses import dataclass

@dataclass
class Message:
    """
    Helper class to create paylaod for a packet.
    """
    _payload: bytes = b""

    def write_mpint(self, x: int, signed: bool = True):
        self._payload += mpint(x, signed=signed)
    
    def write_string(self, t: bytes):
        self._payload += string(t)

    def write_uint32(self, x: int):
        self._payload += uint32(x)
    
    def write_uint64(self, x: int):
        self._payload += uint64(x)

    def write_name_list(self, l: list):
        self._payload += name_list(l)

    def write_byte(self, x: int):
        self._payload += byte(x)

    def __len__(self):
        return len(self._payload)

    @property
    def payload(self):
        return self._payload
    
    @property
    def length(self):
        return len(self._payload)
