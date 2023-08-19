"""
rfc4253#section-6.1
Binary Packet Protocol

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
         is a multiple of the cipher block size or 8, whichever is larger.
         There MUST be at least four bytes of padding.  The
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

class DATA_TYPE:
    ...

    
class SSH_PACKET:
    """
    This class will be called as 
    data = conn.recv()
    packet = SSK_PACKET(data)
    and packet will be a ssh packet object
    """
    def __init__(self, data: bytes):
        # data is a bytes object, we have to decode it
        # uint32    packet_length
        self.packet_length = data[0:4]
        self.packet_length = int.from_bytes(self.packet_length, byteorder='big')

        # byte      padding_length
        self.padding_length = data[4:5]
        self.padding_length = int.from_bytes(self.padding_length, byteorder='big')

        # raw packet MAYBE DELETE
        self.packet = data[4:]

        # byte[n1]  payload; n1 = packet_length - padding_length - 1
        self.payload = data[5:5+self.packet_length-self.padding_length-1]

        # byte[n2]  random padding; n2 = padding_length
        self.random_padding = data[5+self.packet_length-self.padding_length-1:5+self.packet_length-1]

        # byte[m]   mac (Message Authentication Code - MAC); m = mac_length
        self.mac = data[5+self.packet_length-1:5+self.packet_length-1]