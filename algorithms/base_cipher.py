from abc import ABC, abstractmethod

class BaseCipher(ABC):
    @abstractmethod
    def encrypt(self, plaintext: str, **kwargs) -> str:
        """Encrypt the given plaintext using the cipher's algorithm"""
        pass

    @abstractmethod
    def decrypt(self, ciphertext: str, **kwargs) -> str:
        """Decrypt the given ciphertext using the cipher's algorithm"""
        pass

    @abstractmethod
    def validate_parameters(self, **kwargs) -> bool:
        """Validate the parameters required for encryption/decryption"""
        pass

    @abstractmethod
    def generate_parameters(self) -> dict:
        """Generate valid parameters for the cipher"""
        pass 