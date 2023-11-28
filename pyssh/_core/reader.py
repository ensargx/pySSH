from message import Message

class Reader:
    """
    Class to decode a payload into data types
    """
    def __init__(self, message: Message):
        self.message = message
        self.idx = 0
        self.len = len(bytes(message))

    def read_mpint(self, signed: bool = True) -> int:
        """
        By convention, a number that is used in modular computations in
        Z_n SHOULD be represented in the range 0 <= x < n.

        Examples:

            value (hex)        representation (hex)
            -----------        --------------------
            0                  00 00 00 00
            9a378f9b2e332a7    00 00 00 08 09 a3 78 f9 b2 e3 32 a7
            80                 00 00 00 02 00 80
            -1234              00 00 00 02 ed cc
            -deadbeef          00 00 00 05 ff 21 52 41 11
        """
        ...

    def read_uint32(self) -> int:
        ...

    def read_uint64(self) -> int:
        ...
    
    def string(self) -> bytes:
        ...
    
    def name_list(self) -> bytes:
        ...
