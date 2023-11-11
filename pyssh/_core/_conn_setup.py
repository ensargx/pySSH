import re
import gzip

#################################################################################
#                                                                               #
#                            Protocol Version Exchange                          #
#                                                                               #
#################################################################################

def _conn_setup_version_exchange(data: bytes) -> bool:
    """
    When the connection has been established, both sides MUST send an
    identification string.  This identification string MUST be

        SSH-protoversion-softwareversion SP comments CR LF

    Since the protocol being defined in this set of documents is version
    2.0, the 'protoversion' MUST be "2.0".  The 'comments' string is
    OPTIONAL.  If the 'comments' string is included, a 'space' character
    (denoted above as SP, ASCII 32) MUST separate the 'softwareversion'
    and 'comments' strings.  The identification MUST be terminated by a
    single Carriage Return (CR) and a single Line Feed (LF) character
    (ASCII 13 and 10, respectively).  Implementers who wish to maintain
    compatibility with older, undocumented versions of this protocol may
    want to process the identification string without expecting the
    presence of the carriage return character for reasons described in
    Section 5 of this document.  The null character MUST NOT be sent.
    The maximum length of the string is 255 characters, including the
    Carriage Return and Line Feed.

    The part of the identification string preceding the Carriage Return
    and Line Feed is used in the Diffie-Hellman key exchange (see Section
    8).

    The server MAY send other lines of data before sending the version
    string.  Each line SHOULD be terminated by a Carriage Return and Line
    Feed.  Such lines MUST NOT begin with "SSH-", and SHOULD be encoded
    in ISO-10646 UTF-8 [RFC3629] (language is not specified).  Clients
    MUST be able to process such lines.  Such lines MAY be silently
    ignored, or MAY be displayed to the client user.  If they are
    displayed, control character filtering, as discussed in [SSH-ARCH],
    SHOULD be used.  The primary use of this feature is to allow TCP-
    wrappers to display an error message before disconnecting.

    Both the 'protoversion' and 'softwareversion' strings MUST consist of
    printable US-ASCII characters, with the exception of whitespace
    characters and the minus sign (-).  The 'softwareversion' string is
    primarily used to trigger compatibility extensions and to indicate
    the capabilities of an implementation.  The 'comments' string SHOULD
    contain additional information that might be useful in solving user
    problems.  As such, an example of a valid identification string is

        SSH-2.0-billsSSH_3.6.3q3<CR><LF>

    This identification string does not contain the optional 'comments'
    string and is thus terminated by a CR and LF immediately after the
    'softwareversion' string.

    Key exchange will begin immediately after sending this identifier.
    All packets following the identification string SHALL use the binary
    packet protocol, which is described in Section 6.
    """
    
    try:
        data = data.decode('utf-8')
    except:
        # TODO: Implement
        raise NotImplementedError("what to do after ")
        ...

    rex = re.search(r"^SSH-([0-9]\.[0-9])-(.*)( .*)?$",data)

    if rex is None:
        raise NotImplementedError("what to do after if version packet format is not correct")
    
    if rex.group(1) != "2.0":
        raise NotImplementedError("what to do after if version is not 2.0")
    
    return True

#################################################################################
#                                                                               #
#                            Binary Packet Protocol                             #
#                                                                               #
#################################################################################
    
def _binary_packet_protocol():
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
    ...

# Maximum Packet Length
"""
    All implementations MUST be able to process packets with an
    uncompressed payload length of 32768 bytes or less and a total packet
    size of 35000 bytes or less (including 'packet_length',
    'padding_length', 'payload', 'random padding', and 'mac').  The
    maximum of 35000 bytes is an arbitrarily chosen value that is larger
    than the uncompressed length noted above.  Implementations SHOULD
    support longer packets, where they might be needed.  For example, if
    an implementation wants to send a very large number of certificates,
    the larger packets MAY be sent if the identification string indicates
    that the other party is able to process them.  However,
    implementations SHOULD check that the packet length is reasonable in
    order for the implementation to avoid denial of service and/or buffer
    overflow attacks.
"""

#################################################################################
#                                                                               #
#                                Compression                                    #
#                                                                               #
#################################################################################

def _compression(data: bytes):
    """
    If compression has been negotiated, the 'payload' field (and only it)
    will be compressed using the negotiated algorithm.  The
    'packet_length' field and 'mac' will be computed from the compressed
    payload.  Encryption will be done after compression.
    Compression MAY be stateful, depending on the method.  Compression
    MUST be independent for each direction, and implementations MUST
    allow independent choosing of the algorithm for each direction.  In
    practice however, it is RECOMMENDED that the compression method be
    the same in both directions.

    The following compression methods are currently defined:

        none     REQUIRED        no compression
        zlib     OPTIONAL        ZLIB (LZ77) compression

    The "zlib" compression is described in [RFC1950] and in [RFC1951].
    The compression context is initialized after each key exchange, and
    is passed from one packet to the next, with only a partial flush
    being performed at the end of each packet.  A partial flush means
    that the current compressed block is ended and all data will be
    output.  If the current block is not a stored block, one or more
    empty blocks are added after the current block to ensure that there
    are at least 8 bits, counting from the start of the end-of-block code
    of the current block to the end of the packet payload.

    Additional methods may be defined as specified in [SSH-ARCH] and
    [SSH-NUMBERS].
    """
    ...

def _compress_zlib(payload: bytes):
    gzip.compress(payload)

def _decompress_zlib(payload: bytes):
    gzip.decompress(payload)

#################################################################################
#                                                                               #
#                                Encryption                                     #
#                                                                               #
#################################################################################

def _encryption():
    """
    An encryption algorithm and a key will be negotiated during the key
    exchange.  When encryption is in effect, the packet length, padding
    length, payload, and padding fields of each packet MUST be encrypted
    with the given algorithm.

    The encrypted data in all packets sent in one direction SHOULD be
    considered a single data stream.  For example, initialization vectors
    SHOULD be passed from the end of one packet to the beginning of the
    next packet.  All ciphers SHOULD use keys with an effective key
    length of 128 bits or more.

    The ciphers in each direction MUST run independently of each other.
    Implementations MUST allow the algorithm for each direction to be
    independently selected, if multiple algorithms are allowed by local
    policy.  In practice however, it is RECOMMENDED that the same
    algorithm be used in both directions.

    The following ciphers are currently defined:

        3des-cbc         REQUIRED          three-key 3DES in CBC mode
        blowfish-cbc     OPTIONAL          Blowfish in CBC mode
        twofish256-cbc   OPTIONAL          Twofish in CBC mode,
                                            with a 256-bit key
        twofish-cbc      OPTIONAL          alias for "twofish256-cbc"
                                            (this is being retained
                                            for historical reasons)
        twofish192-cbc   OPTIONAL          Twofish with a 192-bit key
        twofish128-cbc   OPTIONAL          Twofish with a 128-bit key
        aes256-cbc       OPTIONAL          AES in CBC mode,
                                            with a 256-bit key
        aes192-cbc       OPTIONAL          AES with a 192-bit key
        aes128-cbc       RECOMMENDED       AES with a 128-bit key
        serpent256-cbc   OPTIONAL          Serpent in CBC mode, with
                                            a 256-bit key
        serpent192-cbc   OPTIONAL          Serpent with a 192-bit key
        serpent128-cbc   OPTIONAL          Serpent with a 128-bit key
        arcfour          OPTIONAL          the ARCFOUR stream cipher
                                            with a 128-bit key
        idea-cbc         OPTIONAL          IDEA in CBC mode
        cast128-cbc      OPTIONAL          CAST-128 in CBC mode
        none             OPTIONAL          no encryption; NOT RECOMMENDED

    The "3des-cbc" cipher is three-key triple-DES (encrypt-decrypt-
    encrypt), where the first 8 bytes of the key are used for the first
    encryption, the next 8 bytes for the decryption, and the following 8
    bytes for the final encryption.  This requires 24 bytes of key data
    (of which 168 bits are actually used).  To implement CBC mode, outer
    chaining MUST be used (i.e., there is only one initialization
    vector).  This is a block cipher with 8-byte blocks.  This algorithm
    is defined in [FIPS-46-3].  Note that since this algorithm only has
    an effective key length of 112 bits ([SCHNEIER]), it does not meet
    the specifications that SSH encryption algorithms should use keys of
    128 bits or more.  However, this algorithm is still REQUIRED for
    historical reasons; essentially, all known implementations at the
    time of this writing support this algorithm, and it is commonly used
    because it is the fundamental interoperable algorithm.  At some
    future time, it is expected that another algorithm, one with better
    strength, will become so prevalent and ubiquitous that the use of
    "3des-cbc" will be deprecated by another STANDARDS ACTION.

    The "blowfish-cbc" cipher is Blowfish in CBC mode, with 128-bit keys
    [SCHNEIER].  This is a block cipher with 8-byte blocks.
    The "twofish-cbc" or "twofish256-cbc" cipher is Twofish in CBC mode,
    with 256-bit keys as described [TWOFISH].  This is a block cipher
    with 16-byte blocks.

    The "twofish192-cbc" cipher is the same as above, but with a 192-bit
    key.

    The "twofish128-cbc" cipher is the same as above, but with a 128-bit
    key.

    The "aes256-cbc" cipher is AES (Advanced Encryption Standard)
    [FIPS-197], in CBC mode.  This version uses a 256-bit key.

    The "aes192-cbc" cipher is the same as above, but with a 192-bit key.

    The "aes128-cbc" cipher is the same as above, but with a 128-bit key.

    The "serpent256-cbc" cipher in CBC mode, with a 256-bit key as
    described in the Serpent AES submission.

    The "serpent192-cbc" cipher is the same as above, but with a 192-bit
    key.

    The "serpent128-cbc" cipher is the same as above, but with a 128-bit
    key.

    The "arcfour" cipher is the Arcfour stream cipher with 128-bit keys.
    The Arcfour cipher is believed to be compatible with the RC4 cipher
    [SCHNEIER].  Arcfour (and RC4) has problems with weak keys, and
    should be used with caution.

    The "idea-cbc" cipher is the IDEA cipher in CBC mode [SCHNEIER].

    The "cast128-cbc" cipher is the CAST-128 cipher in CBC mode with a
    128-bit key [RFC2144].

    The "none" algorithm specifies that no encryption is to be done.
    Note that this method provides no confidentiality protection, and it
    is NOT RECOMMENDED.  Some functionality (e.g., password
    authentication) may be disabled for security reasons if this cipher
    is chosen.

    Additional methods may be defined as specified in [SSH-ARCH] and in
    [SSH-NUMBERS].
    """

#################################################################################
#                                                                               #
#                              Data Integrity                                   #
#                                                                               #
#################################################################################

def _data_integrity():
    """
    Data integrity is protected by including with each packet a MAC that
    is computed from a shared secret, packet sequence number, and the
    contents of the packet.

    The message authentication algorithm and key are negotiated during
    key exchange.  Initially, no MAC will be in effect, and its length
    MUST be zero.  After key exchange, the 'mac' for the selected MAC
    algorithm will be computed before encryption from the concatenation
    of packet data:

        mac = MAC(key, sequence_number || unencrypted_packet)

    where unencrypted_packet is the entire packet without 'mac' (the
    length fields, 'payload' and 'random padding'), and sequence_number
    is an implicit packet sequence number represented as uint32.  The
    sequence_number is initialized to zero for the first packet, and is
    incremented after every packet (regardless of whether encryption or
    MAC is in use).  It is never reset, even if keys/algorithms are
    renegotiated later.  It wraps around to zero after every 2^32
    packets.  The packet sequence_number itself is not included in the
    packet sent over the wire.

    The MAC algorithms for each direction MUST run independently, and
    implementations MUST allow choosing the algorithm independently for
    both directions.  In practice however, it is RECOMMENDED that the
    same algorithm be used in both directions.

    The value of 'mac' resulting from the MAC algorithm MUST be
    transmitted without encryption as the last part of the packet.  The
    number of 'mac' bytes depends on the algorithm chosen.

    The following MAC algorithms are currently defined:

        hmac-sha1    REQUIRED        HMAC-SHA1 (digest length = key
                                    length = 20)
        hmac-sha1-96 RECOMMENDED     first 96 bits of HMAC-SHA1 (digest
                                    length = 12, key length = 20)
        hmac-md5     OPTIONAL        HMAC-MD5 (digest length = key
                                    length = 16)
        hmac-md5-96  OPTIONAL        first 96 bits of HMAC-MD5 (digest
                                    length = 12, key length = 16)
        none         OPTIONAL        no MAC; NOT RECOMMENDED

    The "hmac-*" algorithms are described in [RFC2104].  The "*-n" MACs
    use only the first n bits of the resulting value.

    SHA-1 is described in [FIPS-180-2] and MD5 is described in [RFC1321].

    Additional methods may be defined, as specified in [SSH-ARCH] and in
    [SSH-NUMBERS].
    """

#################################################################################
#                                                                               #
#                            Key Exchange Methods                               #
#                                                                               #
#################################################################################

def _key_exchange_methods():
    """
    The key exchange method specifies how one-time session keys are
    generated for encryption and for authentication, and how the server
    authentication is done.

    Two REQUIRED key exchange methods have been defined:

        diffie-hellman-group1-sha1 REQUIRED
        diffie-hellman-group14-sha1 REQUIRED

    These methods are described in Section 8.

    Additional methods may be defined as specified in [SSH-NUMBERS].  The
    name "diffie-hellman-group1-sha1" is used for a key exchange method
    using an Oakley group, as defined in [RFC2409].  SSH maintains its
    own group identifier space that is logically distinct from Oakley
    [RFC2412] and IKE; however, for one additional group, the Working
    Group adopted the number assigned by [RFC3526], using diffie-
    hellman-group14-sha1 for the name of the second defined group.
    Implementations should treat these names as opaque identifiers and
    should not assume any relationship between the groups used by SSH and
    the groups defined for IKE.
    """
    ...


#################################################################################
#                                                                               #
#                           Public Key Algorithms                               #
#                                                                               #
#################################################################################

def _public_key_algorithms():
    """
    This protocol has been designed to operate with almost any public key
    format, encoding, and algorithm (signature and/or encryption).

    There are several aspects that define a public key type:

    o  Key format: how is the key encoded and how are certificates
        represented.  The key blobs in this protocol MAY contain
        certificates in addition to keys.

    o  Signature and/or encryption algorithms.  Some key types may not
        support both signing and encryption.  Key usage may also be
        restricted by policy statements (e.g., in certificates).  In this
        case, different key types SHOULD be defined for the different
        policy alternatives.

    o  Encoding of signatures and/or encrypted data.  This includes but
        is not limited to padding, byte order, and data formats.

    The following public key and/or certificate formats are currently
    defined:

    ssh-dss           REQUIRED     sign   Raw DSS Key
    ssh-rsa           RECOMMENDED  sign   Raw RSA Key
    pgp-sign-rsa      OPTIONAL     sign   OpenPGP certificates (RSA key)
    pgp-sign-dss      OPTIONAL     sign   OpenPGP certificates (DSS key)

    Additional key types may be defined, as specified in [SSH-ARCH] and
    in [SSH-NUMBERS].

    The key type MUST always be explicitly known (from algorithm
    negotiation or some other source).  It is not normally included in
    the key blob.

    Certificates and public keys are encoded as follows:

        string    certificate or public key format identifier
        byte[n]   key/certificate data

    The certificate part may be a zero length string, but a public key is
    required.  This is the public key that will be used for
    authentication.  The certificate sequence contained in the
    certificate blob can be used to provide authorization.

    Public key/certificate formats that do not explicitly specify a
    signature format identifier MUST use the public key/certificate
    format identifier as the signature identifier.

    Signatures are encoded as follows:

        string    signature format identifier (as specified by the
                public key/certificate format)
        byte[n]   signature blob in format specific encoding.

    The "ssh-dss" key format has the following specific encoding:

        string    "ssh-dss"
        mpint     p
        mpint     q
        mpint     g
        mpint     y

    Here, the 'p', 'q', 'g', and 'y' parameters form the signature key
    blob.

    Signing and verifying using this key format is done according to the
    Digital Signature Standard [FIPS-186-2] using the SHA-1 hash
    [FIPS-180-2].

    The resulting signature is encoded as follows:

        string    "ssh-dss"
        string    dss_signature_blob

    The value for 'dss_signature_blob' is encoded as a string containing
    r, followed by s (which are 160-bit integers, without lengths or
    padding, unsigned, and in network byte order).

    The "ssh-rsa" key format has the following specific encoding:

        string    "ssh-rsa"
        mpint     e
        mpint     n

    Here the 'e' and 'n' parameters form the signature key blob.

    Signing and verifying using this key format is performed according to
    the RSASSA-PKCS1-v1_5 scheme in [RFC3447] using the SHA-1 hash.

    The resulting signature is encoded as follows:

        string    "ssh-rsa"
        string    rsa_signature_blob

    The value for 'rsa_signature_blob' is encoded as a string containing
    s (which is an integer, without lengths or padding, unsigned, and in
    network byte order).

    The "pgp-sign-rsa" method indicates the certificates, the public key,
    and the signature are in OpenPGP compatible binary format
    ([RFC2440]).  This method indicates that the key is an RSA-key.

    The "pgp-sign-dss" is as above, but indicates that the key is a
    DSS-key.
    """
    ...

# Key Exchange

#################################################################################
#                                                                               #
#                               Key Exchange                                    #
#                                                                               #
#################################################################################
