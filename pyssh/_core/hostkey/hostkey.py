from abc import ABC, abstractmethod

class HostKey(ABC):
    @abstractmethod
    def get_name(self):
        pass

    @abstractmethod
    def get_key(self):
        """Returns the public key of the host."""
        pass

    @abstractmethod
    def signature(self):
        pass

class PubKey(ABC):
    @abstractmethod
    def verify(self):
        pass

    @abstractmethod
    def get_key(self):
        pass

class PrivKey(ABC):
    @abstractmethod
    def sign(self):
        pass