from pyssh._core._version import __version__
pySSHbanner = b"SSH-2.0-pySSH_" + __version__.encode("utf-8") + b" byEnsarGok" + b"\r\n"


def _get_pyssh_banner():
    return pySSHbanner

_key_exchange_init = None

def _get_key_exchange_init():
    """
    Key exchange begins by each side sending the following packet:

        byte         SSH_MSG_KEXINIT
        byte[16]     cookie (random bytes)
        name-list    kex_algorithms
        name-list    server_host_key_algorithms
        name-list    encryption_algorithms_client_to_server
        name-list    encryption_algorithms_server_to_client
        name-list    mac_algorithms_client_to_server
        name-list    mac_algorithms_server_to_client
        name-list    compression_algorithms_client_to_server
        name-list    compression_algorithms_server_to_client
        name-list    languages_client_to_server
        name-list    languages_server_to_client
        boolean      first_kex_packet_follows
        uint32       0 (reserved for future extension)

    Each of the algorithm name-lists MUST be a comma-separated list of
    algorithm names (see Algorithm Naming in [SSH-ARCH] and additional
    information in [SSH-NUMBERS]).  Each supported (allowed) algorithm
    MUST be listed in order of preference, from most to least.

    The first algorithm in each name-list MUST be the preferred (guessed)
    algorithm.  Each name-list MUST contain at least one algorithm name.

        cookie
            The 'cookie' MUST be a random value generated by the sender.
            Its purpose is to make it impossible for either side to fully
            determine the keys and the session identifier.

        kex_algorithms
            Key exchange algorithms were defined above.  The first
            algorithm MUST be the preferred (and guessed) algorithm.  If
            both sides make the same guess, that algorithm MUST be used.
            Otherwise, the following algorithm MUST be used to choose a key
            exchange method: Iterate over client's kex algorithms, one at a
            time.  Choose the first algorithm that satisfies the following
            conditions:

            +  the server also supports the algorithm,

            +  if the algorithm requires an encryption-capable host key,
            there is an encryption-capable algorithm on the server's
            server_host_key_algorithms that is also supported by the
            client, and

            +  if the algorithm requires a signature-capable host key,
            there is a signature-capable algorithm on the server's
            server_host_key_algorithms that is also supported by the
            client.

        If no algorithm satisfying all these conditions can be found, the
        connection fails, and both sides MUST disconnect.

        server_host_key_algorithms
            A name-list of the algorithms supported for the server host
            key.  The server lists the algorithms for which it has host
            keys; the client lists the algorithms that it is willing to
            accept.  There MAY be multiple host keys for a host, possibly
            with different algorithms.

            Some host keys may not support both signatures and encryption
            (this can be determined from the algorithm), and thus not all
            host keys are valid for all key exchange methods.

            Algorithm selection depends on whether the chosen key exchange
            algorithm requires a signature or an encryption-capable host
            key.  It MUST be possible to determine this from the public key
            algorithm name.  The first algorithm on the client's name-list
            that satisfies the requirements and is also supported by the
            server MUST be chosen.  If there is no such algorithm, both
            sides MUST disconnect.

        encryption_algorithms
            A name-list of acceptable symmetric encryption algorithms (also
            known as ciphers) in order of preference.  The chosen
            encryption algorithm to each direction MUST be the first
            algorithm on the client's name-list that is also on the
            server's name-list.  If there is no such algorithm, both sides
            MUST disconnect.

            Note that "none" must be explicitly listed if it is to be
            acceptable.  The defined algorithm names are listed in Section
            6.3.

        mac_algorithms
            A name-list of acceptable MAC algorithms in order of
            preference.  The chosen MAC algorithm MUST be the first
            algorithm on the client's name-list that is also on the
            server's name-list.  If there is no such algorithm, both sides
            MUST disconnect.

            Note that "none" must be explicitly listed if it is to be
            acceptable.  The MAC algorithm names are listed in Section 6.4.

        compression_algorithms
            A name-list of acceptable compression algorithms in order of
            preference.  The chosen compression algorithm MUST be the first
            algorithm on the client's name-list that is also on the
            server's name-list.  If there is no such algorithm, both sides
            MUST disconnect.

            Note that "none" must be explicitly listed if it is to be
            acceptable.  The compression algorithm names are listed in
            Section 6.2.

        languages
            This is a name-list of language tags in order of preference
            [RFC3066].  Both parties MAY ignore this name-list.  If there
            are no language preferences, this name-list SHOULD be empty as
            defined in Section 5 of [SSH-ARCH].  Language tags SHOULD NOT
            be present unless they are known to be needed by the sending
            party.

        first_kex_packet_follows
            Indicates whether a guessed key exchange packet follows.  If a
            guessed packet will be sent, this MUST be TRUE.  If no guessed
            packet will be sent, this MUST be FALSE.

            After receiving the SSH_MSG_KEXINIT packet from the other side,
            each party will know whether their guess was right.  If the
            other party's guess was wrong, and this field was TRUE, the
            next packet MUST be silently ignored, and both sides MUST then
            act as determined by the negotiated key exchange method.  If
            the guess was right, key exchange MUST continue using the
            guessed packet.

    After the SSH_MSG_KEXINIT message exchange, the key exchange
    algorithm is run.  It may involve several packet exchanges, as
    specified by the key exchange method.

    Once a party has sent a SSH_MSG_KEXINIT message for key exchange or
    re-exchange, until it has sent a SSH_MSG_NEWKEYS message (Section
    7.3), it MUST NOT send any messages other than:

    o  Transport layer generic messages (1 to 19) (but
        SSH_MSG_SERVICE_REQUEST and SSH_MSG_SERVICE_ACCEPT MUST NOT be
        sent);

    o  Algorithm negotiation messages (20 to 29) (but further
        SSH_MSG_KEXINIT messages MUST NOT be sent);

    o  Specific key exchange method messages (30 to 49).

    The provisions of Section 11 apply to unrecognized messages.

    Note, however, that during a key re-exchange, after sending a
    SSH_MSG_KEXINIT message, each party MUST be prepared to process an
    arbitrary number of messages that may be in-flight before receiving a
    SSH_MSG_KEXINIT message from the other party.
    """
    if globals().get("_key_exchange_init") is not None:
        return _key_exchange_init

    _payload = b"\x14"

    import os
    _payload += os.urandom(16) # cookie
    del os

    algorithms = b"diffie-hellman-group1-sha1,diffie-hellman-group14-sha1"
    _payload += len(algorithms).to_bytes(4, byteorder="big") # kex_algorithms length
    _payload += algorithms

    algorithms = b"ssh-rsa,ssh-dss"
    _payload += len(algorithms).to_bytes(4, byteorder="big") # server_host_key_algorithms length
    _payload += algorithms

    algorithms = b"3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr"
    _payload += len(algorithms).to_bytes(4, byteorder="big") # encryption_algorithms_client_to_server length
    _payload += algorithms

    algorithms = b"3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr"
    _payload += len(algorithms).to_bytes(4, byteorder="big") # encryption_algorithms_server_to_client length
    _payload += algorithms

    algorithms = b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
    _payload += len(algorithms).to_bytes(4, byteorder="big") # mac_algorithms_client_to_server length
    _payload += algorithms

    algorithms = b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1"
    _payload += len(algorithms).to_bytes(4, byteorder="big") # mac_algorithms_server_to_client length
    _payload += algorithms

    algorithms = b"none,zlib"
    _payload += len(algorithms).to_bytes(4, byteorder="big") # compression_algorithms_client_to_server length
    _payload += algorithms

    algorithms = b"none,zlib"
    _payload += len(algorithms).to_bytes(4, byteorder="big") # compression_algorithms_server_to_client length
    _payload += algorithms

    _payload += b"\x00\x00\x00\x00" # languages_client_to_server length
    _payload += b"\x00\x00\x00\x00" # languages_server_to_client length

    _payload += b"\x00" # first_kex_packet_follows

    _payload += b"\x00\x00\x00\x00" # reserved for future extension

    globals()["_key_exchange_init"] = _payload
    return _payload