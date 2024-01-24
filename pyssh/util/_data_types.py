from typing import Iterable


def mpint(x: int, signed: bool = True) -> bytes:
    """
    Represents multiple precision integers in two's complement format,
    stored as a string, 8 bits per byte, MSB first.  Negative numbers
    have the value 1 as the most significant bit of the first byte of
    the data partition.  If the most significant bit would be set for
    a positive number, the number MUST be preceded by a zero byte.
    Unnecessary leading bytes with the value 0 or 255 MUST NOT be
    included.  The value zero MUST be stored as a string with zero
    bytes of data.

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

    # Check if x is bytes
    if isinstance(x, bytes):
        x = int.from_bytes(x, byteorder='big', signed=signed)

    # Get the absolute value of x
    abs_x = abs(x)

    # Convert the absolute value to bytes
    abs_bytes = bytearray()
    for _ in range((abs_x.bit_length() + 7) // 8):
        abs_bytes.append(abs_x & 0xFF)
        abs_x >>= 8

    if signed and x < 0:
        # Take the two's complement of abs_bytes
        if abs_bytes[-1] & 0x80:
            abs_bytes.append(0x00)
        for i in range(len(abs_bytes)):
            abs_bytes[i] ^= 0xFF
        abs_bytes[0] += 1

    if signed and x >= 0 and abs_bytes and abs_bytes[-1] & 0x80:
        abs_bytes.append(0x00)

    abs_bytes.reverse()

    # Add the length as a 32-bit integer in network byte order
    length_bytes = len(abs_bytes).to_bytes(4, byteorder='big')

    return length_bytes + bytes(abs_bytes)

def uint32(x: int) -> bytes:
    """
      Represents a 32-bit unsigned integer.  Stored as four bytes in the
      order of decreasing significance (network byte order).  For
      example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4 aa.
    """
    return x.to_bytes(4, byteorder='big', signed=False)

def uint64(x: int) -> bytes:
    """
    Represents a 64-bit unsigned integer.  Stored as eight bytes in
    the order of decreasing significance (network byte order).
    """
    return x.to_bytes(8, byteorder='big', signed=False)

def int32(x: int) -> bytes:
    """
    Represents a 32-bit signed integer.  Stored as four bytes in the
    order of decreasing significance (network byte order).  Positive
    numbers have the value 0x80000000 as the most significant byte of
    the data partition.  Negative numbers have the value 0x7fffffff as
    the most significant byte of the data partition.  For example: the
    value -1 is stored as ff ff ff ff.
    """
    return x.to_bytes(4, byteorder='big', signed=True)

def int64(x: int) -> bytes:
    """
    Represents a 64-bit signed integer.  Stored as eight bytes in the
    order of decreasing significance (network byte order).  Positive
    numbers have the value 0x8000000000000000 as the most significant
    byte of the data partition.  Negative numbers have the value
    0x7fffffffffffffff as the most significant byte of the data
    partition.
    """
    return x.to_bytes(8, byteorder='big', signed=True)

def boolean(x: bool) -> bytes:
    """
    Represents a boolean.  The value FALSE is represented by the byte
    value 0x00 and the value TRUE is represented by the byte value 0x01.
    """
    if x:
        return b'\x01'
    return b'\x00'

def string(z: bytes) -> bytes:
    """
      Arbitrary length binary string.  Strings are allowed to contain
      arbitrary binary data, including null characters and 8-bit
      characters.  They are stored as a uint32 containing its length
      (number of bytes that follow) and zero (= empty string) or more
      bytes that are the value of the string.  Terminating null
      characters are not used.

      Strings are also used to store text.  In that case, US-ASCII is
      used for internal names, and ISO-10646 UTF-8 for text that might
      be displayed to the user.  The terminating null character SHOULD
      NOT normally be stored in the string.  For example: the US-ASCII
      string "testing" is represented as 00 00 00 07 t e s t i n g.  The
      UTF-8 mapping does not alter the encoding of US-ASCII characters.
    """
    length_bytes = uint32(len(z))
    if isinstance(z, str):
        return length_bytes + z.encode('utf-8')
    return length_bytes + z

def name_list(l: Iterable[bytes]):
    """
    A string containing a comma-separated list of names.  A name-list
    is represented as a uint32 containing its length (number of bytes
    that follow) followed by a comma-separated list of zero or more
    names.  A name MUST have a non-zero length, and it MUST NOT
    contain a comma (",").  As this is a list of names, all of the
    elements contained are names and MUST be in US-ASCII.  Context may
    impose additional restrictions on the names.  For example, the
    names in a name-list may have to be a list of valid algorithm
    identifiers (see Section 6 below), or a list of [RFC3066] language
    tags.  The order of the names in a name-list may or may not be
    significant.  Again, this depends on the context in which the list
    is used.  Terminating null characters MUST NOT be used, neither
    for the individual names, nor for the list as a whole.

    Examples:

    value                      representation (hex)
    -----                      --------------------
    (), the empty name-list    00 00 00 00
    ("zlib")                   00 00 00 04 7a 6c 69 62
    ("zlib,none")              00 00 00 09 7a 6c 69 62 2c 6e 6f 6e 65
    """
    # l must be an iterable of strings
    # if z is ("zlib") then l is ["zlib"] BUT python will treat it as a string, not a list
    # if z is ("zlib,none") then l is ["zlib", "none"]
    return string(b','.join(l))

def byte(x: int = 0) -> bytes:
    """
    Represents an 8-bit unsigned number.  Stored as a single byte.
    """
    return x.to_bytes(1, byteorder='big', signed=False)
