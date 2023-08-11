class SSHException():
    def __new__():
        return "SSH Exception"

class WrongVersionException(SSHException):
    def __new__():
        return "Version Failed"