from _util import mpint, string, uint32, uint64, name_list, byte


class Message:
    """
    Helper class to create paylaod for a packet.
    """
    def __init__(self):
        self.payload = b""

    def add_mpint(self, x: int, signed: bool = True):
        self.payload += mpint(x, signed=signed)
    
    def add_string(self, t: bytes):
        self.payload += string(t)

    def add_uint32(self, x: int):
        self.payload += uint32(x)
    
    def add_uint64(self, x: int):
        self.payload += uint64(x)

    def add_name_list(self, l: list):
        self.payload += name_list(l)

    def add_byte(self, x: int):
        self.payload += byte(x)

    def __bytes__(self):
        return self.payload
    
    def payload(self):
        return self.payload