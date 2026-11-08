"""
SecureVault - Classical Cryptography: Vigenère Cipher
Implements polyalphabetic substitution cipher.
NOTE: Vigenère Cipher is a classical algorithm vulnerable to frequency analysis
and Kasiski examination. It is utilized here as Stage 1 in a Super-Encryption pipeline
(Vigenère + AES-256-GCM) for educational and multilayer defense demonstration.
"""

class VigenereCipher:
    """
    Polyalphabetic substitution cipher implementation with case preservation
    and non-alphabetic character pass-through.
    """

    @staticmethod
    def _clean_key(key: str) -> str:
        """Sanitize and validate key."""
        clean = "".join([c for c in key if c.isalpha()])
        if not clean:
            raise ValueError("Kunci Vigenère harus mengandung setidaknya satu karakter alfabet.")
        return clean

    @classmethod
    def encrypt(cls, plaintext: str, key: str) -> str:
        """
        Encrypt plaintext using Vigenère cipher.
        Uppercase and lowercase letters are shifted within their respective ranges;
        punctuation, numbers, and whitespace remain unchanged.
        """
        clean_key = cls._clean_key(key)
        ciphertext = []
        key_len = len(clean_key)
        key_idx = 0

        for char in plaintext:
            if char.isalpha():
                shift = ord(clean_key[key_idx % key_len].upper()) - ord('A')
                if char.isupper():
                    enc_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
                else:
                    enc_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))
                ciphertext.append(enc_char)
                key_idx += 1
            else:
                ciphertext.append(char)

        return "".join(ciphertext)

    @classmethod
    def decrypt(cls, ciphertext: str, key: str) -> str:
        """
        Decrypt ciphertext using Vigenère cipher.
        """
        clean_key = cls._clean_key(key)
        plaintext = []
        key_len = len(clean_key)
        key_idx = 0

        for char in ciphertext:
            if char.isalpha():
                shift = ord(clean_key[key_idx % key_len].upper()) - ord('A')
                if char.isupper():
                    dec_char = chr((ord(char) - ord('A') - shift) % 26 + ord('A'))
                else:
                    dec_char = chr((ord(char) - ord('a') - shift) % 26 + ord('a'))
                plaintext.append(dec_char)
                key_idx += 1
            else:
                plaintext.append(char)

        return "".join(plaintext)
