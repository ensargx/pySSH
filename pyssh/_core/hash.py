import hashlib

class Hash:

    @staticmethod
    def SHA1(data: bytes):
        return hashlib.sha1(data).digest()
