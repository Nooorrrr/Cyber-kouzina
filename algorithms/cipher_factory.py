from typing import Dict, Type
from .base_cipher import BaseCipher
from .classic.caesar import CaesarCipher
from .classic.xor import XORCipher
from .classic.vigenere import VigenereCipher
from .classic.affine import AffineCipher
from .classic.base64_cipher import Base64Cipher
from .symmetric.aes import AESCipher
from .symmetric.des import DESCipher
from .symmetric.rc4 import RC4Cipher
from .asymmetric.rsa import RSACipher
from .asymmetric.diffie_hellman import DiffieHellmanCipher
from .asymmetric.elgamal import ElGamalCipher

class CipherFactory:
    _ciphers: Dict[str, Type[BaseCipher]] = {
        # Classic ciphers
        'caesar': CaesarCipher,
        'xor': XORCipher,
        'vigenere': VigenereCipher,
        'affine': AffineCipher,
        'base64': Base64Cipher,
        
        # Symmetric ciphers
        'aes': AESCipher,
        'des': DESCipher,
        'rc4': RC4Cipher,
        
        # Asymmetric ciphers
        'rsa': RSACipher,
        'diffie-hellman': DiffieHellmanCipher,
        'elgamal': ElGamalCipher,
    }
    
    @classmethod
    def get_cipher(cls, cipher_name: str) -> BaseCipher:
        """Get a cipher instance by name"""
        cipher_class = cls._ciphers.get(cipher_name.lower())
        if cipher_class is None:
            raise ValueError(f"Unknown cipher: {cipher_name}")
        return cipher_class()
    
    @classmethod
    def register_cipher(cls, name: str, cipher_class: Type[BaseCipher]):
        """Register a new cipher implementation"""
        cls._ciphers[name.lower()] = cipher_class
    
    @classmethod
    def get_available_ciphers(cls) -> list:
        """Get a list of all available cipher names"""
        return list(cls._ciphers.keys())
    
    @classmethod
    def get_ciphers_by_type(cls, cipher_type: str) -> list:
        """Get a list of cipher names by type"""
        type_map = {
            'classic': ['caesar', 'xor', 'vigenere', 'affine', 'base64'],
            'symmetric': ['aes', 'des', 'rc4'],
            'asymmetric': ['rsa', 'diffie-hellman', 'elgamal']
        }
        return type_map.get(cipher_type.lower(), []) 