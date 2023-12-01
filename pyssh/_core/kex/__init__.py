from .dh import (
    DHGroup1SHA1,
    DHGroup14SHA1
)

from typing import Protocol
class KeyExchangeProtocol(Protocol):
    def generate_y(self):
        pass

    def generate_f(self):
        pass

    def compute_k(self):
        pass

    def generate_h(self, data: bytes):
        pass
