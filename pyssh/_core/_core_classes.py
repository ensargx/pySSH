import struct

class _core_packet:   # TODO: Add try-except for struct.unpack, and raise NotImplementedError if it fails
    """
    Each packet is in the following format:

    uint32    packet_length
    byte      padding_length
    byte[n1]  payload; n1 = packet_length - padding_length - 1
    byte[n2]  random padding; n2 = padding_length
    byte[m]   mac (Message Authentication Code - MAC); m = mac_length

    packet_length
        The length of the packet in bytes, not including 'mac' or the
        'packet_length' field itself.

    padding_length
        Length of 'random padding' (bytes).

    payload
        The useful contents of the packet.  If compression has been
        negotiated, this field is compressed.  Initially, compression
        MUST be "none".

    random padding
        Arbitrary-length padding, such that the total length of
        (packet_length || padding_length || payload || random padding)
        is a multiple of the cipher block size or 8, whichever is
            larger.  There MUST be at least four bytes of padding.  The
        padding SHOULD consist of random bytes.  The maximum amount of
        padding is 255 bytes.

    mac
        Message Authentication Code.  If message authentication has
        been negotiated, this field contains the MAC bytes.  Initially,
        the MAC algorithm MUST be "none".

    Note that the length of the concatenation of 'packet_length',
    'padding_length', 'payload', and 'random padding' MUST be a multiple
    of the cipher block size or 8, whichever is larger.  This constraint
    MUST be enforced, even when using stream ciphers.  Note that the
    'packet_length' field is also encrypted, and processing it requires
    special care when sending or receiving packets.  Also note that the
    insertion of variable amounts of 'random padding' may help thwart
    traffic analysis.

    The minimum size of a packet is 16 (or the cipher block size,
    whichever is larger) bytes (plus 'mac').  Implementations SHOULD
    decrypt the length after receiving the first 8 (or cipher block size,
    whichever is larger) bytes of a packet.
    """

    def __init__(self, data: bytes):
        """
        uint32    packet_length
        byte      padding_length
        byte[n1]  payload; n1 = packet_length - padding_length - 1
        byte[n2]  random padding; n2 = padding_length
        byte[m]   mac (Message Authentication Code - MAC); m = mac_length

        packet_length
         The length of the packet in bytes, not including 'mac' or the
         'packet_length' field itself.

        padding_length
            Length of 'random padding' (bytes).

        payload
            The useful contents of the packet.  If compression has been
            negotiated, this field is compressed.  Initially, compression
            MUST be "none".

        random padding
            Arbitrary-length padding, such that the total length of
            (packet_length || padding_length || payload || random padding)
            is a multiple of the cipher block size or 8, whichever is
            larger.  There MUST be at least four bytes of padding.  The
            padding SHOULD consist of random bytes.  The maximum amount of
            padding is 255 bytes.

        mac
            Message Authentication Code.  If message authentication has
            been negotiated, this field contains the MAC bytes.  Initially,
            the MAC algorithm MUST be "none".
        """
        
        _packet_length = data[:4]
        _packet_length = struct.unpack(">I", _packet_length)[0]
        self.packet_length = _packet_length

        _padding_length = data[4]
        self.padding_length = _padding_length

        _payload = data[5:5+_packet_length-_padding_length-1]
        self.payload = _payload

        _random_padding = data[5+_packet_length-_padding_length-1:5+_packet_length-_padding_length-1+_padding_length]
        self.random_padding = _random_padding

        _mac = data[5+_packet_length-_padding_length-1+_padding_length:]
        self.mac = _mac

    def __repr__(self):
        return f"<_packet_format packet_length={self.packet_length} padding_length={self.padding_length} payload={self.payload} random_padding={self.random_padding} mac={self.mac}>"
    
    def __str__(self):
        return f"<_packet_format packet_length={self.packet_length} padding_length={self.padding_length} payload={self.payload} random_padding={self.random_padding} mac={self.mac}>"
    
    def __bytes__(self):
        return self.packet_length.to_bytes(4, byteorder="big") + self.padding_length.to_bytes(1, byteorder="big") + self.payload + self.random_padding + self.mac
    
    def __len__(self):
        return len(bytes(self))
    
    @staticmethod
    def _create_packet(_payload, _mac = b""):
        """
        Creates a packet from given payload.
        """
        _len_payload = len(_payload) + 1 # +1 for padding_length
        
        # _len_payload + 4 + _len_random_padding = MUST be a multiple
        # of the cipher block size or 8, whichever is larger 

        _len_random_padding = 8 - (_len_payload + 4) % 8
        if _len_random_padding < 4:
            _len_random_padding += 8

        _padding_length = _len_random_padding
        _packet_length = _len_payload + _len_random_padding

        _random_padding = b"\0" * _len_random_padding

        _packet = _core_packet(_packet_length.to_bytes(4, byteorder="big") + _padding_length.to_bytes(1, byteorder="big") + _payload + _random_padding + _mac)
        return _packet

