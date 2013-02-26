#!/usr/bin/env python
# coding=utf8

"""
This module implements a number of classical cryptographic algorithms. All of
these should considered broken; they are provided for educational and historical
purposes, not security.
"""

import string

try:
    from itertools import izip
except ImportError:
    izip = zip


from . import util


class Cipher(object):
    """
    Base class for all ciphers. Don't instantiate this.
    """
    def encrypt(self, text):
        raise NotImplementedError

    def decrypt(self, text):
        raise NotImplementedError

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.key)

class Polybius(dict):
    """
    A representation of a Polybius square.

    This automatically constructs a square out of a key and an alphabet, and
    exposes a mapping from letters to (row, column) tuples and vice versa.
    """
    def __init__(self, key, alphabet='abcdefghiklmnopqrstuvwxyz'):
        """
        All key characters must occur in the alphabet.
        """
        super(dict, self).__init__()

        self.key = key
        self.alphabet = alphabet

        # We don't need to be 5×5, but we do need to be square.
        self.side = int(len(alphabet) ** .5)
        if self.side * self.side != len(alphabet):
            raise ValueError("Can't map alphabet onto a square!")

        # We need a mapping from letters to row/col numbers...
        n = 0
        for c in key + alphabet:
            if c not in self:
                self[c] = (n // self.side, n % self.side)
                n += 1

        if len(self) != len(alphabet):
            raise ValueError('Invalid key or alphabet!')

        # ... and vice versa.
        for k in list(self.keys()):
            self[self[k]] = k

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.key, self.alphabet)

    def __str__(self):
        return '\n'.join(' '.join(self[(r, c)] for c in range(self.side))
                         for r in range(self.side))


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


class Affine(MonoalphabeticSubstitutionCipher):
    """
    The affine cipher is a monoalphabetic substitution cipher that maps each
    letter of the alphabet to another one through a simple mathematical
    function. Its key consists of two integers, a and b, the first of which
    must be prime relative to the length of the alphabet.

    To encrypt a letter, it is transformed into a number (A becomes 0, B
    becomes 1, etc.), which is multiplied by a and incremented by b modulo the
    length of the alphabet. The resulting number is turned back into a letter.

    The decryption step is the same in reverse: the number is decremented by b
    and multiplied by a's multiplicative inverse modulo the length of the
    alphabet.
    """
    def __init__(self, key, alphabet='abcdefghijklmnopqrstuvwxyz'):
        """
        key is a tuple of integers, the first of which must be prime relative
        to the length of the alphabet.
        """
        self.alphabet = alphabet.lower()
        self.key = key
        a, b = key

        # Decryption mapping.
        # Doing this one first so we don't have to waste time if a doesn't
        # have a multiplicative inverse modulo len(alphabet).
        mmi = util.mmi(a, len(alphabet))
        self.decrypt_mapping = dict(
            (c, alphabet[mmi * (alphabet.index(c) - b) % len(alphabet)])
            for c in alphabet
        )

        # Encryption mapping.
        self.encrypt_mapping = dict(
            (c, alphabet[(a * alphabet.index(c) + b) % len(alphabet)])
            for c in alphabet
        )

    def __repr__(self):
        return '%s(%r, alphabet=%r)' % (self.__class__.__name__,
                                        self.key, self.alphabet)

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

    def __repr__(self):
        return '%s(alphabet=%r)' % (self.__class__.__name__, self.alphabet)

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

class Keyword(MonoalphabeticSubstitutionCipher):
    """
    The keyword cipher is a monoalphabetic substitution cipher using a keyword
    as the key. The alphabet is appended to the key, and duplicate letters are
    removed. The result is then aligned with the plaintext alphabet to obtain
    the substitution mapping.

    For example, with the key "SECRET":

    Plaintext:  A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
    Ciphertext: S E C R T A B D F G H I J K L M N O P Q U V W X Y Z
    """
    def __init__(self, key):
        self.key = key.lower()
        m = []
        for c in key + string.ascii_lowercase:
            if c not in m:
                m.append(c)
        self.encrypt_mapping = dict(zip(string.ascii_lowercase, m))
        self.decrypt_mapping = dict(zip(m, string.ascii_lowercase))

class Playfair(MonoalphabeticSubstitutionCipher):
    """
    The Playfair cipher is a digraph substitution cipher invented by Charles
    Wheatstone in 1854 and popularised by Lord Playfair.
    """
    def __init__(self, key, breaker='x', padding='z', omitted={'j': 'i'}):
        """
        key is a short string.
        breaker is the letter with which duplicate pairs are broken up.
        omitted is a mapping. ({'q': ''} is common).
        """
        # Ensure omitted is proper and lowercase.
        if not isinstance(omitted, dict):
            raise ValueError('omitted must be a dict!')
        self.omitted = dict((k.lower(), v.lower()) for k, v in omitted.items())

        # Adjust the alphabet to take omitted into account.
        self.alphabet = ''.join(c for c in string.ascii_lowercase
                                if c not in self.omitted)
        if len(self.alphabet) != 25 or \
           any(len(c) > 1 or c not in self.alphabet
               for c in self.omitted.values()):
            raise ValueError('Malformed omitted!')

        # Ensure the breaker is alright.
        self.breaker = breaker
        if len(breaker) != 1 or breaker not in self.alphabet:
            raise ValueError('Breaker %s not in alphabet!' % breaker)

        # Ensure the padding is alright.
        self.padding = padding
        if len(padding) != 1 or padding not in self.alphabet:
            raise ValueError('Padding %s not in alphabet!' % padding)

        # Clean the key.
        self.key = key
        key = ''.join(c for c in key.lower() if c in self.alphabet)

        # Construct the Polybius square.
        self.polybius = Polybius(key, self.alphabet)

    # Playfair is a monoalphabetic substitution cipher, but because it
    # works with bigrams rather than individual letters, we can't reuse
    # MonoalphabeticSubstitutionCipher's methods.

    def encrypt(self, text):
        """
        Turn provided plaintext into ciphertext.
        """
        return ''.join(self.__polyb(b) for b in self.__plain_pairs(text))

    def decrypt(self, text):
        """
        Turn provided ciphertext into plaintext.
        """
        return ''.join(self.__polyb(b, True) for b in self.__cipher_pairs(text))

    def __plain_pairs(self, text):
        """
        Turns plaintext into proper digraphs (tuples) for encryption.
        """
        # Convert mappings.
        text = ''.join(self.omitted.get(c, c) for c in text)

        # Get rid of repeated breaker characters.
        while self.breaker + self.breaker in text:
            text = text.replace(self.breaker + self.breaker, self.breaker)

        # Pad.
        text += self.padding

        plain = (c for c in text.lower() if c in self.alphabet)
        for a, b in izip(plain, plain):
            if a == b:
                yield a, self.breaker
                c = next(plain)
                while c == b:
                    yield b, self.breaker
                    c = next(plain)
                yield b, c
            else:
                yield a, b

    def __cipher_pairs(self, text):
        """
        Turns ciphertext into proper digraphs (tuples) for decryption.
        Will raise ValueError is ciphertext is bogus.
        """
        if len(text) % 2 != 0:
            raise ValueError('Ciphertext of uneven length!')
        cipher = (self.omitted.get(c, c) for c in text)
        for a, b in zip(cipher, cipher):
            if a == b:
                raise ValueError('Invalid ciphertext!')
            yield a, b

    def __polyb(self, digraph, decrypt=False):
        """
        Translates a digraph through the Polybius square.
        """
        r1, c1 = self.polybius[digraph[0]]
        r2, c2 = self.polybius[digraph[1]]

        if r1 != r2 and c1 != c2:
            return self.polybius[(r1, c2)] + self.polybius[(r2, c1)]
        elif r1 == r2:
            if decrypt:
                c1 = (c1 - 1) % 5
                c2 = (c2 - 1) % 5
            else:
                c1 = (c1 + 1) % 5
                c2 = (c2 + 1) % 5
        elif c1 == c2:
            if decrypt:
                r1 = (r1 - 1) % 5
                r2 = (r2 - 1) % 5
            else:
                r1 = (r1 + 1) % 5
                r2 = (r2 + 1) % 5
        return self.polybius[(r1, c1)] + self.polybius[(r2, c2)]

    def __repr__(self):
        return '%s(%r, breaker=%r, padding=%r, omitted=%r)' % \
               (self.__class__.__name__, self.key, self.breaker, self.padding,
                self.omitted)

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

    def __repr__(self):
        return '%s()' % self.__class__.__name__

class Simple(MonoalphabeticSubstitutionCipher):
    """
    The simplest substitution cipher just maps characters to other characters.
    """
    def __init__(self, key):
        """
        key: a dict mapping characters to other characters.
        """
        self.key = dict(key)
        self.encrypt_mapping = self.key
        self.decrypt_mapping = dict((b, a) for (a, b) in self.key.items())


# Transposition ciphers

class Column(Cipher):
    """
    The columnar transposition cipher is a fairly straightforward transposition
    cipher, which permutes plaintext in two steps.

    First, the plaintext is padded until its length is a multiple of the key
    length and placed into columns below the key, as follows:

        C I P H E R
        t h i s i s
        a n e x a m
        p l e x x x

    In this example, the plaintext is "thisisanexample", the key is "CIPHER",
    and the padding character is "x".

    In the second step, the columns are moved so that the key's characters are
    in alphabetical order:

        C E H I P R
        t i s h i s
        a a x n e m
        p x x l e x

    Then the key row is removed, and the columns are catenated to form the
    ciphertext; in this case, "tapiaxsxxhnlieesmx".

    By itself, the columnar transposition cipher is fairly easy to break, but
    it continued to be used as part of more complex encryption schemes until
    some time into the 1950s.
    """
    def __init__(self, key, pad='x'):
        """
        key is a short string with no repeated characters.
        pad is a single character.
        """
        if len(key) < 1:
            raise ValueError('Invalid key!')
        for c in key:
            if key.count(c) > 1:
                raise ValueError('Each key character must be unique!')
        self.key = key

        if len(pad) != 1:
            raise ValueError('pad must be one character!')
        self.pad = pad

    def encrypt(self, text):
        """
        Encrypts the provided plaintext.
        """
        # Pad the plaintext until it's rectangular.
        if len(text) % len(self.key):
            text += self.pad * (len(self.key) - len(text) % len(self.key))

        # Assemble the columns.
        columns = [text[i::len(self.key)] for i in range(len(self.key))]

        # Index them by ciphertext character and sort alphabetically.
        columns = dict((k, v) for k, v in zip(self.key, columns))
        return ''.join(columns[k] for k in sorted(self.key))

    def decrypt(self, text):
        """
        Decrypts the provided ciphertext.
        """
        if len(text) % len(self.key) != 0:
            raise ValueError('Not a valid ciphertext.')
        rows = len(text) // len(self.key)

        # Break the ciphertext up in columns.
        columns = [text[i * rows:(i + 1) * rows] for i in range(len(self.key))]

        # Index the columns by their key character.
        columns = dict((k, c) for k, c in zip(sorted(self.key), columns))

        # Restore their original order.
        columns = [columns[c] for c in self.key]

        # Just read off the plaintext.
        return ''.join(''.join(row) for row in zip(*columns)).rstrip(self.pad)

    def __repr__(self):
        return '%s(%r, pad=%r)' % (self.__class__.__name__, self.key, self.pad)
