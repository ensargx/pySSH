
def select_algorithm(type: str, algorithms: str):
    """
    Gerekli algoritmay return eder, eğer algoritma yoksa hata frlatr.

    @type: str [kex, host_key, mac, public_key, compression]
    @algorithms: str
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

# Host Key Algorithm
def rsa_sha2_512(payload):
    print("rsa_sha2_512")
    raise NotImplementedError
    return None

host_key_algorithms = {'rsa-sha2-512': rsa_sha2_512}

# Key Exchange Algorithm
def sntrup(payload):
    print("snrtup")
    raise NotImplementedError
    return None

kex_algorithms = {'sntrup761x25519-sha512@openssh.com': sntrup}


def kex_get_methods(payload):
    """
    Gets the methods from the kexinit message and returns them as a dictionary
    """
    #rest will depend on the message code
    cookie = payload[1:17]
    end_payload_index = 17

    kex_algorithms_length = int.from_bytes(payload[end_payload_index:21], byteorder='big')
    kex_algorithms = payload[21:21 + kex_algorithms_length] 
    end_payload_index += 4 + kex_algorithms_length

    server_host_key_algorithms_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    server_host_key_algorithms = payload[end_payload_index + 4:end_payload_index + 4 + server_host_key_algorithms_length] # truncated
    end_payload_index += 4 + server_host_key_algorithms_length

    encryption_algorithms_client_to_server_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    encryption_algorithms_client_to_server = payload[end_payload_index + 4:end_payload_index + 4 + encryption_algorithms_client_to_server_length] # truncated
    end_payload_index += 4 + encryption_algorithms_client_to_server_length

    encryption_algorithms_server_to_client_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    encryption_algorithms_server_to_client = payload[end_payload_index + 4:end_payload_index + 4 + encryption_algorithms_server_to_client_length] # truncated
    end_payload_index += 4 + encryption_algorithms_server_to_client_length

    mac_algorithms_client_to_server_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    mac_algorithms_client_to_server = payload[end_payload_index + 4:end_payload_index + 4 + mac_algorithms_client_to_server_length] # truncated
    end_payload_index += 4 + mac_algorithms_client_to_server_length

    mac_algorithms_server_to_client_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    mac_algorithms_server_to_client = payload[end_payload_index + 4:end_payload_index + 4 + mac_algorithms_server_to_client_length] # truncated
    end_payload_index += 4 + mac_algorithms_server_to_client_length

    compression_algorithms_client_to_server_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    compression_algorithms_client_to_server = payload[end_payload_index + 4:end_payload_index + 4 + compression_algorithms_client_to_server_length] # truncated
    end_payload_index += 4 + compression_algorithms_client_to_server_length

    compression_algorithms_server_to_client_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    compression_algorithms_server_to_client = payload[end_payload_index + 4:end_payload_index + 4 + compression_algorithms_server_to_client_length] # truncated
    end_payload_index += 4 + compression_algorithms_server_to_client_length

    languages_client_to_server_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    languages_client_to_server = payload[end_payload_index + 4:end_payload_index + 4 + languages_client_to_server_length] # truncated
    end_payload_index += 4 + languages_client_to_server_length

    languages_server_to_client_length = int.from_bytes(payload[end_payload_index:end_payload_index + 4], byteorder='big')
    languages_server_to_client = payload[end_payload_index + 4:end_payload_index + 4 + languages_server_to_client_length] # truncated
    end_payload_index += 4 + languages_server_to_client_length

    first_kex_packet_follows = payload[end_payload_index:end_payload_index + 1]
    end_payload_index += 1

    reserved = payload[end_payload_index:end_payload_index + 4]

    return {"kex" : "kex"}
