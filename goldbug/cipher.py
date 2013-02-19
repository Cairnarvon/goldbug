#!/usr/bin/env python
# coding=utf8

"""
This module implements a number of classical cryptographic algorithms. All of
these should considered broken; they are provided for educational and historical
purposes, not security.
"""

class Cipher(object):
    """
    Base class for all ciphers. Don't instantiate this.
    """
    def encrypt(self, text):
        raise NotImplementedError

    def decrypt(self, text):
        raise NotImplementedError


# Substitution ciphers

class Atbash(Cipher):
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
        self.mapping = dict(zip(self.alphabet, self.alphabet[::-1]))

    def encrypt(self, text, strip=False):
        """
        Encrypts the given text. Plaintext case will be preserved in the
        ciphertext, to the extent that this makes sense.
        """
        if strip:
            text = filter(lambda c: c.lower() in self.alphabet, text)
        return ''.join((type(text).lower, type(text).upper)[c.isupper()]\
                       (self.mapping.get(c.lower(), c)) for c in text)

    decrypt = encrypt

class Caesar(Cipher):
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

    def encrypt(self, text, strip=False):
        """
        Encrypts the given text.
        
        If strip is True, non-alphabetic characters (including spaces) are
        removed before encryption; otherwise, they are preserved and will be
        in the ciphertext unmolested.
        """
        if strip:
            text = filter(str.isalpha, text)
        return ''.join(map(lambda c: self.__shift(c, self.key), text))

    def decrypt(self, text):
        """
        Decrypts the given text.
        """
        return ''.join(map(lambda c: self.__shift(c, 26 - self.key), text))

    def __shift(self, c, key):
        if 'a' <= c <= 'z':
            return chr(ord('a') + (ord(c) - ord('a') + key) % 26)
        if 'A' <= c <= 'Z':
            return chr(ord('A') + (ord(c) - ord('A') + key) % 26)
        return c

class Rot13(Caesar):
    """
    ROT13 is a special case of the Caesar cipher. In effect, it is the Caesar
    cipher with the key set to 13. It is a reciprocal cipher, meaning two
    successive applications will yield the original text.

    It became particularly popular on Usenet, where it was often used to
    obscure spoilers and punchlines to jokes.
    """
    def __init__(self):
        self.key = 13
