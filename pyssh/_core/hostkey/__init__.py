from .hostkey import HostKey

from .ssh_rsa import RSAKey

host_key_algorithms = {
    b"ssh-rsa": RSAKey
}