from .base_cryptanalysis import BaseCryptanalysis
from collections import Counter
import math

class KasiskiTest(BaseCryptanalysis):
    def __init__(self):
        super().__init__()
        self.name = "Kasiski Test"
        self.description = "Kasiski examination for finding the Vigenère cipher key length"
        self.target_cipher = "vigenere"
        self.min_pattern_length = 3
    
    def analyze(self, ciphertext: str, **kwargs) -> dict:
        if not self.validate_parameters(**kwargs):
            raise ValueError("Invalid parameters")
        
        # Convert to uppercase and remove non-alphabetic characters
        ciphertext = ''.join(c.upper() for c in ciphertext if c.isalpha())
        
        # Find repeated sequences
        sequences = self._find_repeated_sequences(ciphertext)
        
        # Calculate possible key lengths from the distances
        key_lengths = self._calculate_key_lengths(sequences)
        
        # Attempt to break the cipher for each likely key length
        results = {}
        for key_length in key_lengths[:3]:  # Try top 3 most likely key lengths
            key = self._find_key(ciphertext, key_length)
            results[key_length] = {
                'key': key,
                'confidence': self._calculate_confidence(key_length, sequences)
            }
        
        return results
    
    def _find_repeated_sequences(self, text: str) -> dict:
        """Find repeated sequences in the text and their positions"""
        sequences = {}
        
        # Look for patterns of length 3 to 5
        for length in range(self.min_pattern_length, 6):
            for i in range(len(text) - length + 1):
                pattern = text[i:i + length]
                if pattern in sequences:
                    sequences[pattern].append(i)
                else:
                    sequences[pattern] = [i]
        
        # Keep only patterns that appear more than once
        return {k: v for k, v in sequences.items() if len(v) > 1}
    
    def _calculate_key_lengths(self, sequences: dict) -> list:
        """Calculate possible key lengths from sequence distances"""
        distances = []
        
        for positions in sequences.values():
            for i in range(len(positions) - 1):
                for j in range(i + 1, len(positions)):
                    distance = positions[j] - positions[i]
                    if distance > 0:
                        distances.append(distance)
        
        # Find the factors of all distances
        factors = []
        for distance in distances:
            factors.extend(self._get_factors(distance))
        
        # Count factor frequencies and sort by most common
        factor_counts = Counter(factors)
        return sorted(factor_counts, key=lambda x: (-factor_counts[x], x))
    
    def _get_factors(self, n: int) -> list:
        """Get all factors of a number"""
        factors = []
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                factors.append(i)
                if i != n // i:
                    factors.append(n // i)
        return factors
    
    def _find_key(self, text: str, key_length: int) -> str:
        """Find the most likely key of given length"""
        key = ""
        
        # Split text into groups based on key length
        for i in range(key_length):
            column = text[i::key_length]
            
            # Find the most likely shift for this position
            frequencies = [0] * 26
            for c in column:
                frequencies[ord(c) - ord('A')] += 1
                
            # Find shift that produces letter frequencies closest to English
            best_shift = self._find_best_shift(frequencies)
            key += chr((best_shift + ord('A')) % 26)
        
        return key
    
    def _find_best_shift(self, frequencies: list) -> int:
        """Find the shift that produces letter frequencies closest to English"""
        english_freqs = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0,
            'N': 6.7, 'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3,
            'L': 4.0, 'C': 2.8, 'U': 2.8, 'M': 2.4, 'W': 2.4,
            'F': 2.2, 'G': 2.0, 'Y': 2.0, 'P': 1.9, 'B': 1.5,
            'V': 1.0, 'K': 0.8, 'J': 0.2, 'X': 0.2, 'Q': 0.1,
            'Z': 0.1
        }
        
        best_score = float('-inf')
        best_shift = 0
        
        total = sum(frequencies)
        if total == 0:
            return 0
        
        for shift in range(26):
            score = 0
            for i in range(26):
                shifted = (i - shift) % 26
                freq = (frequencies[i] / total) * 100
                expected = english_freqs[chr(shifted + ord('A'))]
                score -= abs(freq - expected)
            
            if score > best_score:
                best_score = score
                best_shift = shift
        
        return best_shift
    
    def _calculate_confidence(self, key_length: int, sequences: dict) -> float:
        """Calculate confidence score for a key length"""
        matching_seqs = sum(1 for positions in sequences.values()
                          if any(abs(positions[i] - positions[i-1]) % key_length == 0
                               for i in range(1, len(positions))))
        return matching_seqs / len(sequences) if sequences else 0
    
    def validate_parameters(self, **kwargs) -> bool:
        """No additional parameters needed for Kasiski test"""
        return True
