


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
