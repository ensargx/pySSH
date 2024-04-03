from typing import List

class Reader:
    """
    Class to decode a payload into data types
    """
    def __init__(self, message: bytes):
        self._message = message
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
        l = self.read_uint32()
        x = self._message[self.idx:self.idx+l]
        self.idx += l
        return int.from_bytes(x, byteorder="big", signed=signed)

    def read_uint32(self) -> int:
        """
        Represents a 32-bit unsigned integer.  Stored as four bytes in the
        order of decreasing significance (network byte order).  For
        example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4 aa.
        """
        if self.idx + 4 > self.len:
            raise ValueError("Not enough bytes to read uint32")
        val = int.from_bytes(self._message[self.idx:self.idx+4], byteorder="big", signed=False)
        self.idx += 4
        return val

    def read_uint64(self) -> int:
        """
        Represents a 64-bit unsigned integer.  Stored as eight bytes in
        the order of decreasing significance (network byte order).
        """
        if self.idx + 8 > self.len:
            raise ValueError("Not enough bytes to read uint64")
        val = int.from_bytes(self._message[self.idx:self.idx+8], byteorder="big", signed=False)
        self.idx += 8
        return val
    
    def read_string(self) -> bytes:
        """
        Represents an arbitrary length binary string.  Strings are allowed
        to contain arbitrary binary data, including null characters and
        8-bit characters.  They are stored as a uint32 containing its
        length (number of bytes that follow) and zero (= empty string) or
        more bytes that are the value of the string.  Terminating null
        characters are not used.
        """
        l = self.read_uint32()
        assert self.idx + l <= self.len, "Not enough bytes to read string"
        val = self._message[self.idx:self.idx+l]
        self.idx += l
        return val
    
    def read_name_list(self) -> List[bytes]:
        """
        Represents an arbitrary length name string.  Strings are allowed
        to contain arbitrary binary data, including null characters and
        8-bit characters.  They are stored as a uint32 containing its
        length (number of bytes that follow) and zero (= empty string) or
        more bytes that are the value of the string.  Terminating null
        characters are not used.
        """
        l = self.read_uint32()
        assert self.idx + l <= self.len, "Not enough bytes to read name list"
        val = self._message[self.idx:self.idx+l]
        self.idx += l
        return list(val.split(b","))

    def read_byte(self) -> int:
        """
        Represents an arbitrary length binary string.  Strings are allowed
        to contain arbitrary binary data, including null characters and
        8-bit characters.  They are stored as a uint32 containing its
        length (number of bytes that follow) and zero (= empty string) or
        more bytes that are the value of the string.  Terminating null
        characters are not used.
        """
        assert self.idx + 1 <= self.len, "Not enough bytes to read byte"
        val = self._message[self.idx]
        self.idx += 1
        return val

    def read_bytes(self, n: int) -> bytes:
        """
        Represents an arbitrary length binary string.  Strings are allowed
        to contain arbitrary binary data, including null characters and
        8-bit characters.  They are stored as a uint32 containing its
        length (number of bytes that follow) and zero (= empty string) or
        more bytes that are the value of the string.  Terminating null
        characters are not used.
        """
        assert self.idx + n <= self.len, "Not enough bytes to read bytes"
        val = self._message[self.idx:self.idx+n]
        self.idx += n
        return val
    
    def read_boolean(self) -> bool:
        """
        Represents a boolean.  The value FALSE is represented by the
        byte value 0, and the value TRUE by the byte value 1.
        """
        val = self.read_byte()
        if val == 0:
            return False
        return True

    @property
    def message(self):
        return self._message
