from .base_cryptanalysis import BaseCryptanalysis
from collections import Counter
import math

class FrequencyAnalysis(BaseCryptanalysis):
    def __init__(self):
        super().__init__()
        self.name = "Frequency Analysis"
        self.description = "Analyzes letter frequencies to break simple substitution ciphers"
        self.target_cipher = "monoalphabetic"
        
        # English letter frequencies (from most to least common)
        self.english_freqs = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
            'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
            'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4,
            'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5,
            'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2, 'Q': 0.1,
            'Z': 0.1
        }
        
        # Common English digrams
        self.common_digrams = [
            'TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ON', 'AT', 'EN', 'ND',
            'TI', 'ES', 'OR', 'TE', 'OF', 'ED', 'IS', 'IT', 'AL', 'AR'
        ]
        
    def analyze(self, ciphertext: str, **kwargs) -> dict:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Convert to uppercase and remove non-alphabetic characters
        text = ''.join(c.upper() for c in ciphertext if c.isalpha())
        
        # Get letter frequencies
        frequencies = self._get_letter_frequencies(text)
        
        # Get digram frequencies
        digrams = self._get_digram_frequencies(text)
        
        # Try to identify substitutions
        substitutions = self._identify_substitutions(frequencies, digrams)
        
        # Attempt partial decryption
        partial_decrypt = self._apply_substitutions(text, substitutions)
        
        return {
            'frequencies': frequencies,
            'digrams': digrams,
            'likely_substitutions': substitutions,
            'partial_decrypt': partial_decrypt,
            'confidence': self._calculate_confidence(frequencies)
        }
    
    def _get_letter_frequencies(self, text: str) -> dict:
        """Calculate letter frequencies in the text"""
        total = len(text)
        counter = Counter(text)
        return {char: (count / total) * 100 
                for char, count in counter.items()}
    
    def _get_digram_frequencies(self, text: str) -> dict:
        """Calculate digram (two-letter) frequencies"""
        digrams = [''.join(pair) for pair in zip(text, text[1:])]
        total = len(digrams)
        counter = Counter(digrams)
        return {digram: (count / total) * 100 
                for digram, count in counter.most_common(20)}
    
    def _identify_substitutions(self, frequencies: dict, digrams: dict) -> dict:
        """Identify possible letter substitutions based on frequencies"""
        substitutions = {}
        
        # Sort both frequency lists
        cipher_freqs = sorted(frequencies.items(), key=lambda x: x[1], reverse=True)
        eng_freqs = sorted(self.english_freqs.items(), key=lambda x: x[1], reverse=True)
        
        # Match most frequent letters
        for (cipher_char, _), (eng_char, _) in zip(cipher_freqs, eng_freqs):
            confidence = self._calculate_frequency_match_confidence(
                frequencies.get(cipher_char, 0),
                self.english_freqs.get(eng_char, 0)
            )
            substitutions[cipher_char] = {
                'likely_plain': eng_char,
                'confidence': confidence
            }
        
        return substitutions
    
    def _calculate_frequency_match_confidence(self, observed: float, expected: float) -> float:
        """Calculate confidence in a frequency match"""
        # Lower difference means higher confidence
        diff = abs(observed - expected)
        # Convert to a 0-1 scale where 0 means maximum difference (100)
        # and 1 means perfect match
        return 1 - (diff / 100)
    
    def _apply_substitutions(self, text: str, substitutions: dict) -> str:
        """Apply identified substitutions to get partial decryption"""
        result = ""
        for char in text:
            sub = substitutions.get(char)
            if sub and sub['confidence'] > 0.5:  # Only use high confidence substitutions
                result += sub['likely_plain']
            else:
                result += '*'  # Use * for unknown letters
        return result
    
    def _calculate_confidence(self, frequencies: dict) -> float:
        """Calculate overall confidence in the analysis"""
        total_diff = 0
        count = 0
        
        for letter, freq in frequencies.items():
            if letter in self.english_freqs:
                total_diff += abs(freq - self.english_freqs[letter])
                count += 1
        
        if count == 0:
            return 0
        
        # Convert to a 0-1 scale where 0 means maximum difference
        # and 1 means perfect match
        max_possible_diff = 100 * 26  # Maximum possible difference
        return 1 - (total_diff / max_possible_diff)
    
    def validate_parameters(self, **kwargs) -> bool:
        """No additional parameters needed for frequency analysis"""
        return True
