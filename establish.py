import re

def check_version(client, address):
    version = client.recv(1024)
    version = version.decode("utf-8")

    # check version from ssh banner
    rex = re.search(r"^SSH-([0-9]\.[0-9])-(.*)( .*)?$",version)

    # check if packet is a valid ssh packet
    if not rex:
        """
        Client will not be accepted if it is not a valid ssh client
        """
        return False
    
    # check if version is 2.0
    if rex.group(1) != "2.0":
        """
        Only version 2.0 is supported
        """
        return False
    
    # send version to client
    client.send("SSH-2.0-pySSH byEnsarGok\r\n".encode('utf-8'))
    return True

def key_exchange(client, address):
    data = client.recv(2048)
    packet_length = int.from_bytes(data[0:4], byteorder='big')
    padding_length = int.from_bytes(data[4:5], byteorder='big')
    payload = data[5:packet_length - padding_length+5]
    mac = data[packet_length + padding_length + 4:packet_length + padding_length + 5]
    message_code = payload[0:1]
    message_code = int.from_bytes(message_code, byteorder='big')
    if message_code == 20:  # SSH_MSG_KEXINIT (20)
        pass
