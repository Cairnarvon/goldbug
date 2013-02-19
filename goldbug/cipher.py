#!/usr/bin/env python
# coding=utf8

"""
This module implements a number of classical cryptographic algorithms. All of
these should considered broken; they are provided for educational and historical
purposes, not security.
"""

import string

class Cipher(object):
    """
    Base class for all ciphers. Don't instantiate this.
    """
    def encrypt(self, text):
        raise NotImplementedError

    def decrypt(self, text):
        raise NotImplementedError


# Substitution ciphers

class MonoalphabeticSubstitutionCipher(Cipher):
    """
    Abstract base class for ciphers that use monoalphabetic substitutions.
    """
    def encrypt(self, text):
        """
        Encrypts the given text. Plaintext case will be preserved in the
        ciphertext, to the extent that this makes sense.
        """
        return ''.join((type(text).lower, type(text).upper)[c.isupper()]\
                       (self.encrypt_mapping.get(c.lower(), c)) for c in text)

    def decrypt(self, text):
        """
        Decrypts the given text. Ciphertext case will be preserved in the
        plaintext, to the extent that this makes sense.
        """
        return ''.join((type(text).lower, type(text).upper)[c.isupper()]\
                       (self.decrypt_mapping.get(c.lower(), c)) for c in text)


class Atbash(MonoalphabeticSubstitutionCipher):
    """
    Atbash is a keyless substitution cipher, originally for the Hebrew
    alphabet. It consists of substituting the first letter of the alphabet for
    the last, the second for the penultimate, and so on; hence the name (אתבש).
    It is a reciprocal cipher, meaning two successive applications will yield
    the original plaintext.

    This implementation works on the 26-letter Latin alphabet by default.
    """
    def __init__(self, alphabet="abcdefghijklmnopqrstuvwxyz"):
        """
        alphabet is the alphabet to use, in the right order.
        """
        self.alphabet = alphabet.lower()
        self.encrypt_mapping = dict(zip(self.alphabet, self.alphabet[::-1]))
        self.decrypt_mapping = self.encrypt_mapping

class Caesar(MonoalphabeticSubstitutionCipher):
    """
    The Caesar cipher, also known as the shift cipher or Caesar shift, is a
    monoalphabetic substitution cipher in which each letter of the alphabet is
    replaced by a letter some fixed number of positions down the alphabet.
    This number is the key.

    It is named after Julius Caesar, who supposedly used it for his personal
    correspondence.
    """
    def __init__(self, key):
        """
        key should be an integer, practically between 0 and 26.
        """
        self.key = int(key) % 26
        shifted = [chr(ord('a') + (ord(c) - ord('a') + key) % 26) for c in
                   string.ascii_lowercase]
        self.encrypt_mapping = dict(zip(string.ascii_lowercase, shifted))
        self.decrypt_mapping = dict(zip(shifted, string.ascii_lowercase))

class Rot13(Caesar):
    """
    ROT13 is a special case of the Caesar cipher. In effect, it is the Caesar
    cipher with the key set to 13. It is a reciprocal cipher, meaning two
    successive applications will yield the original text.

    It became particularly popular on Usenet, where it was often used to
    obscure spoilers and punchlines to jokes.
    """
    def __init__(self):
        super(Rot13, self).__init__(13)
