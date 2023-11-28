from ._util import mpint, string, uint32, uint64, name_list, byte

from dataclasses import dataclass

@dataclass
class Message:
    """
    Helper class to create paylaod for a packet.
    """
    _payload: bytes = b""
    _repr_body: str = ""

    def write_mpint(self, x: int, signed: bool = True):
        self._repr_body += f"<mpint({x})>"
        self._payload += mpint(x, signed=signed)
    
    def write_string(self, t: bytes):
        self._repr_body += f"<string({t})>"
        self._payload += string(t)

    def write_uint32(self, x: int):
        self._repr_body += f"<uint32({x})>"
        self._payload += uint32(x)
    
    def write_uint64(self, x: int):
        self._repr_body += f"<uint64({x})>"
        self._payload += uint64(x)

    def write_name_list(self, l: list):
        self._repr_body += f"<name_list({l})>"
        self._payload += name_list(l)

    def write_byte(self, x: int):
        self._repr_body += f"<byte({x})>"
        self._payload += byte(x)

    def __len__(self):
        return len(self._payload)
    
    @property
    def payload(self):
        return self._payload
    
    @property
    def length(self):
        return len(self._payload)
    
    def __repr__(self):
        return f"Message({self._repr_body})"
