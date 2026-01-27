from abc import ABC, abstractmethod

class CryptoBase(ABC):

    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        pass

    @abstractmethod
    def decrypt(self, data: bytes, key: bytes) -> bytes:
        pass
