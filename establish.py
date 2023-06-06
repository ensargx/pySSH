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
