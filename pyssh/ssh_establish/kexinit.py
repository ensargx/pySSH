
def select_algorithm(type: str, algorithms: bytes):
    """
    Gerekli algoritmay return eder, eğer algoritma yoksa hata frlatr.

    @type: str [kex, host_key, mac, public_key, compression]
    @algorithms: bytes
    @return: function
    """
    algorithms = algorithms.decode("utf-8").split(",")
    my_dict = f"{type}_algorithms"
    my_dict = globals().get(my_dict)
    for algo in algorithms:
        function = my_dict.get(algo)
        if function:
            return function
    raise Exception("No matching kex algorithm, fix here later")


def curve25519_sha256(payload):
    print("curve25519_sha256")
    raise NotImplementedError
    return None

def curve25519_sha256_libssh_org(payload: bytes):
    """
    Verify that client public key
    length is 32 bytes.
    Generate ephemeral key pair.
    Compute shared secret.
    Generate and sign exchange hash.

    @payload: bytes
    @return: bytes
    """

    # Verify that client public key length is 32 bytes.
    client_public_key_length = int.from_bytes(payload[0:4], byteorder='big')
    if client_public_key_length != 32:
        raise Exception("Client public key length is not 32 bytes")
    
    # Generate ephemeral key pair.
    

    print("curve25519_sha256_libssh_org")
    raise NotImplementedError
    return None

def ecdh_sha2_nistp256(payload):
    print("ecdh_sha2_nistp256")
    raise NotImplementedError
    return None

def ecdh_sha2_nistp384(payload):
    print("ecdh_sha2_nistp384")
    raise NotImplementedError
    return None

def ecdh_sha2_nistp521(payload):
    print("ecdh_sha2_nistp521")
    raise NotImplementedError
    return None

def diffie_hellman_group_exchange_sha256(payload):
    print("diffie_hellman_group_exchange_sha256")
    raise NotImplementedError
    return None

def diffie_hellman_group16_sha512(payload):
    print("diffie_hellman_group16_sha512")
    raise NotImplementedError
    return None

def diffie_hellman_group18_sha512(payload):
    print("diffie_hellman_group18_sha512")
    raise NotImplementedError
    return None

def diffie_hellman_group14_sha256(payload):
    print("diffie_hellman_group14_sha256")
    raise NotImplementedError
    return None

def diffie_hellman_group14_sha1(payload):
    print("diffie_hellman_group14_sha1")
    raise NotImplementedError
    return None

def diffie_hellman_group_exchange_sha1(payload):
    print("diffie_hellman_group_exchange_sha1")
    raise NotImplementedError
    return None

kex_algorithms = {
    'curve25519-sha256': curve25519_sha256,
    'curve25519-sha256@libssh.org': curve25519_sha256_libssh_org,
    'ecdh-sha2-nistp256': ecdh_sha2_nistp256,
    'ecdh-sha2-nistp384': ecdh_sha2_nistp384,
    'ecdh-sha2-nistp521': ecdh_sha2_nistp521,
    'diffie-hellman-group-exchange-sha256': diffie_hellman_group_exchange_sha256,
    'diffie-hellman-group16-sha512': diffie_hellman_group16_sha512,
    'diffie-hellman-group18-sha512': diffie_hellman_group18_sha512,
    'diffie-hellman-group14-sha256': diffie_hellman_group14_sha256,
    'diffie-hellman-group14-sha1': diffie_hellman_group14_sha1,
    'diffie-hellman-group-exchange-sha1': diffie_hellman_group_exchange_sha1,
    }


# Host Key Algorithm
def rsa_sha2_512(payload):
    print("rsa_sha2_512")
    raise NotImplementedError
    return None


host_key_algorithms = {'rsa-sha2-512': rsa_sha2_512}







# Encryption Algorithm Client to Server
def chacha20_poly1305_open_ssh(payload):
    print("chacha20_poly1305_open_ssh")
    raise NotImplementedError
    return None

encryption_client_to_server_algorithms = {
    'chaca': chacha20_poly1305_open_ssh,
    'aes128-ctr': None,
}



# Encryption Algorithm Server to Client 
def chacha20_poly1305_open_ssh(payload):
    print("chacha20_poly1305_open_ssh")
    raise NotImplementedError
    return None


encryption_server_to_client_algorithms = {
    'chaca': chacha20_poly1305_open_ssh,
    'aes128-ctr': None,
}



# MAC Algorithm Client to Server
def umac_64_etm_open_ssh(payload):
    print("umac_64_etm_open_ssh")
    raise NotImplementedError
    return None

mac_client_to_server_algorithms = {
    'umac': umac_64_etm_open_ssh,
}


# MAC Algorithm Server to Client

def umac_64_etm_open_ssh(payload):
    print("umac_64_etm_open_ssh")
    raise NotImplementedError
    return None

mac_server_to_client_algorithms = {
    'umac': umac_64_etm_open_ssh,
}


# Compression Algorithm Client to Server
def asdasdasd(payload):
    print("asdasdasd")
    raise NotImplementedError
    return None

compression_client_to_server_algorithms = {
    'deneme': asdasdasd,
}


# Compression Algorithm Server to Client
def asdasdasd(payload):
    print("asdasdasd")
    raise NotImplementedError
    return None

compression_server_to_client_algorithms = {
    'deneme': asdasdasd,
}


def kex_get_methods(payload: bytes):
    """
    Gets the methods from the kexinit message and returns them as a dictionary
    """
    #rest will depend on the message code
    cookie = payload[1:17]
    end_payload_index = 17

    kex_algorithms_length = int.from_bytes(payload[end_payload_index:21], byteorder='big')
    kex_algorithms = payload[21:21 + kex_algorithms_length]
    kex_algorithm = select_algorithm("kex", kex_algorithms)
    end_payload_index += 4 + kex_algorithms_length

    server_host_key_algorithms_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    server_host_key_algorithms = payload[end_payload_index + 4:end_payload_index + 4 + server_host_key_algorithms_length] # truncated
    server_host_key_algorithm = select_algorithm("host_key", server_host_key_algorithms)
    end_payload_index += 4 + server_host_key_algorithms_length

    encryption_algorithms_client_to_server_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    encryption_algorithms_client_to_server = payload[end_payload_index + 4:end_payload_index + 4 + encryption_algorithms_client_to_server_length] # truncated
    encryption_algorithm_client_to_server = select_algorithm("encryption_client_to_server", encryption_algorithms_client_to_server)
    end_payload_index += 4 + encryption_algorithms_client_to_server_length

    encryption_algorithms_server_to_client_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    encryption_algorithms_server_to_client = payload[end_payload_index + 4:end_payload_index + 4 + encryption_algorithms_server_to_client_length] # truncated
    encryption_algorithm_server_to_client = select_algorithm("encryption_server_to_client", encryption_algorithms_server_to_client)
    end_payload_index += 4 + encryption_algorithms_server_to_client_length

    mac_algorithms_client_to_server_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    mac_algorithms_client_to_server = payload[end_payload_index + 4:end_payload_index + 4 + mac_algorithms_client_to_server_length] # truncated
    mac_algorithm_client_to_server = select_algorithm("mac_client_to_server", mac_algorithms_client_to_server)
    end_payload_index += 4 + mac_algorithms_client_to_server_length

    mac_algorithms_server_to_client_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    mac_algorithms_server_to_client = payload[end_payload_index + 4:end_payload_index + 4 + mac_algorithms_server_to_client_length] # truncated
    mac_algorithm_server_to_client = select_algorithm("mac_server_to_client", mac_algorithms_server_to_client)
    end_payload_index += 4 + mac_algorithms_server_to_client_length

    compression_algorithms_client_to_server_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    compression_algorithms_client_to_server = payload[end_payload_index + 4:end_payload_index + 4 + compression_algorithms_client_to_server_length] # truncated
    compression_algorithm_client_to_server = select_algorithm("compression_client_to_server", compression_algorithms_client_to_server)
    end_payload_index += 4 + compression_algorithms_client_to_server_length

    compression_algorithms_server_to_client_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    compression_algorithms_server_to_client = payload[end_payload_index + 4:end_payload_index + 4 + compression_algorithms_server_to_client_length] # truncated
    compression_algorithm_server_to_client = select_algorithm("compression_server_to_client", compression_algorithms_server_to_client)
    end_payload_index += 4 + compression_algorithms_server_to_client_length

    languages_client_to_server_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    languages_client_to_server = payload[end_payload_index + 4:end_payload_index + 4 + languages_client_to_server_length] # truncated
    languages_client_to_server = languages_client_to_server.decode("utf-8").split(",")
    end_payload_index += 4 + languages_client_to_server_length

    languages_server_to_client_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    languages_server_to_client = payload[end_payload_index + 4:end_payload_index + 4 + languages_server_to_client_length] # truncated
    languages_server_to_client = languages_server_to_client.decode("utf-8").split(",")
    end_payload_index += 4 + languages_server_to_client_length

    first_kex_packet_follows = payload[end_payload_index:end_payload_index + 1]
    end_payload_index += 1

    reserved = payload[end_payload_index:end_payload_index + 4]

    return {
        "cookie": cookie,
        "kex_algorithm": kex_algorithm,
        "server_host_key_algorithm": server_host_key_algorithm,
        "encryption_algorithm_client_to_server": encryption_algorithm_client_to_server,
        "encryption_algorithm_server_to_client": encryption_algorithm_server_to_client,
        "mac_algorithm_client_to_server": mac_algorithm_client_to_server,
        "mac_algorithm_server_to_client": mac_algorithm_server_to_client,
        "compression_algorithm_client_to_server": compression_algorithm_client_to_server,
        "compression_algorithm_server_to_client": compression_algorithm_server_to_client,
        "languages_client_to_server": languages_client_to_server,
        "languages_server_to_client": languages_server_to_client,
        "first_kex_packet_follows": first_kex_packet_follows,
        "reserved": reserved
    }