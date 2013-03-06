#!/usr/bin/env python
# coding=utf8

"""
Utilities for use with classical ciphers.
"""

import collections
import string


class Matrix(object):
    """
    Straightforward matrix for your enjoyment.
    """
    def __init__(self, matrix=None, size=None):
        """
        matrix is a sequences of rows. If omitted, size must be given either
        as a natural number representing the size of a square matrix, or a
        tuple representing (rows, columns); this size will be used to construct
        a null matrix.
        """
        if matrix is not None and size is None:
            self.rows = len(matrix)
            self.cols = len(matrix[0])
            self.values = []
            for row in matrix:
                if len(row) != self.cols:
                    raise ValueError('Malformed matrix!')
                self.values.append(list(row))
        elif size is not None and matrix is None:
            if hasattr(size, '__len__'):
                self.rows = int(size[0])
                self.cols = int(size[1])
            else:
                self.rows = self.cols = int(size)
            if self.rows < 1 or self.cols < 1:
                raise ValueError('Invalid size!')
            self.values = [[0] * self.cols for _ in range(self.rows)]
        else:
            raise ValueError('Specify either matrix or size!')

    def row(self, n):
        return self.values[n]

    def col(self, n):
        return list(list(zip(*self.values))[n])

    def __getitem__(self, key):
        if not hasattr(key, '__len__') or len(key) != 2:
            raise KeyError('Bad key: %r' % key)
        return self.values[key[0]][key[1]]

    def __setitem__(self, key, value):
        if not hasattr(key, '__len__') or len(key) != 2:
            raise KeyError('Bad key: %r' % key)
        self.values[key[0]][key[1]] = value

    def __eq__(self, other):
        return self.values == other.values

    def __neq__(self, other):
        return self.values != other.values

    def __add__(self, other):
        if isinstance(other, Matrix):
            # Matrix addition
            if self.rows != other.rows or self.cols != other.cols:
                raise ValueError("Can't add matrices of different sizes!")
            result = Matrix([row[:] for row in self.values])
            for i in range(self.rows):
                for j in range(self.cols):
                    result[i, j] += other[i, j]
            return result
        else:
            # Scalar addition
            return Matrix([[i + other for i in row] for row in self.values])

    def __mul__(self, other):
        if isinstance(other, Matrix):
            # Matrix multiplication
            if self.cols != other.rows:
                raise ValueError("Can't multiply %dx%d by %dx%d!" %
                                 (self.rows, self.cols, other.rows, other.cols))
            result = Matrix(size=(self.rows, other.cols))
            for i in range(result.rows):
                for j in range(result.cols):
                    result[i, j] = sum(a * b for (a, b)
                                       in zip(self.row(i), other.col(j)))
            return result
        else:
            # Scalar multiplication
            return Matrix([[i * other for i in row] for row in self.values])

    def __mod__(self, modulus):
        modulus = int(modulus)
        return Matrix([[i % modulus for i in row] for row in self.values])

    def __pow__(self, power, modulus=None):
        if int(power) != power:
            raise ValueError('Can only raise matrices to integral values!')

        # Positive integral powers are easy.
        if power > 0:
            m = Matrix(self.values) # Copy to avoid trouble if power is 1
            for i in range(power - 1):
                m *= self
            if modulus is not None:
                m %= modulus
            return m

        # The only other power we do is -1.
        if power != -1:
            raise ValueError('Invalid power!')
        if self.rows != self.cols:
            raise ValueError('Only square matrices are invertible!')

        # We're only doing this for the Hill cipher, so...
        if modulus is None:
            raise NotImplementedError('Need a modulus, sorry.')

        # Extend our matrix with the identity matrix.
        v = [row[:] for row in self.values]
        for i in range(self.rows):
            ext = [0] * self.rows
            ext[i] = 1
            v[i].extend(ext)

        # Gauss-Jordan.
        for i in range(self.rows):
            # Normalise
            try:
                multiplier = mmi(v[i][i] % modulus, modulus)
            except ValueError:
                raise ValueError('Matrix is not invertible modulo %d!' %
                                 modulus)
            for j in range(len(v[i])):
                v[i][j] = (v[i][j] * multiplier) % modulus

            # Sweep
            for j in range(self.rows):
                if i == j:
                    continue
                multiplier = v[j][i]
                for k in range(len(v[i])):
                    v[j][k] = (v[j][k] - multiplier * v[i][k]) % modulus

        # Separate out our results.
        return Matrix([row[len(row) // 3 + 1:] for row in v])

    def __str__(self):
        if isinstance(self.values[0][0], int):
            w = 0
            for row in self.values:
                for v in row:
                    if abs(v) > w:
                        w = v
            f = '%%%dd' % (len(str(w)) + int(w < 0))
        else:
            f = '%.2f'
        return '\n'.join(' '.join(f % v for v in row) for row in self.values)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.values)

class Polybius(dict):
    """
    A representation of a Polybius square.

    This automatically constructs a square out of a key and an alphabet, and
    exposes a mapping from letters to (row, column) tuples and vice versa.
    """
    def __init__(self, key, alphabet='abcdefghiklmnopqrstuvwxyz', dimensions=2):
        """
        All key characters must occur in the alphabet.
        """
        super(dict, self).__init__()

        self.key = key
        self.alphabet = alphabet

        # Get rid of duplicate characters in key.
        k = []
        for c in key:
            if c not in k:
                k.append(c)
        key = ''.join(k)

        # Alphabet isn't allowed to have duplicates at all.
        if len(set(alphabet)) != len(alphabet):
            raise ValueError('Alphabet is not a set!')

        # All key characters should occur in the alphabet.
        if not all(c in alphabet for c in key):
            raise ValueError('Invalid key!')

        # Keep track of contents for convenience.
        if alphabet:
            key = ''.join(c for c in key if c in alphabet)
        self.contents = key + ''.join(c for c in alphabet if c not in key)

        self.dimensions = int(dimensions)
        if self.dimensions < 1:
            raise ValueError('Dimension must be positive!')

        # We don't need to be 5×5, but we do need to be regular.
        self.side = int(round(len(self.contents) ** (1.0 / self.dimensions)))
        if self.side ** self.dimensions != len(self.contents):
            raise ValueError("Can't map key + alphabet onto a square!")

        # We need a mapping from letters to row/col numbers...
        for n, c in enumerate(self.contents):
            self[c] = self.__index_to_coordinate(n)

        # ... and vice versa.
        for k in list(self.keys()):
            self[self[k]] = k

    def __index_to_coordinate(self, index):
        co, the_index = (), index
        for i in range(self.dimensions):
            quo, rem = divmod(index, self.side)
            co = (rem,) + co
            index = quo
        if index != 0:
            raise OverflowError('Index %d is out of range!' % the_index)
        return co

    def __repr__(self):
        return '%s(%r, %r)' % (self.__class__.__name__, self.key, self.alphabet)

    def __str__(self):
        if self.dimensions == 1:
            return self[0,]
        elif self.dimensions == 2:
            return '\n'.join(' '.join(self[(r, c)] for c in range(self.side))
                             for r in range(self.side))
        else:
            return repr(self)

class TabulaRecta(dict):
    """
    A representation of the tabula recta for a given alphabet.
    """
    def __init__(self, alphabet=string.ascii_lowercase, reverse=False):
        super(dict, self).__init__()

        if len(set(alphabet)) != len(alphabet):
            raise ValueError('Alphabet has duplicates!')

        self.reverse = reverse
        self.alphabet = alphabet
        for a in alphabet:
            for b in alphabet:
                if not reverse:
                    self[a, b] = alphabet[(alphabet.index(a) +
                                           alphabet.index(b)) % len(alphabet)]
                else:
                    self[a, b] = alphabet[(alphabet.index(a) -
                                           alphabet.index(b)) % len(alphabet)]

    def __repr__(self):
        if self.reverse:
            return '%s(%r, reverse=True)' % (self.__class__.__name__,
                                             self.alphabet)
        else:
            return '%s(%r)' % (self.__class__.__name__, self.alphabet)


def egcd(a, b):
    """
    Extended Euclidean algorithm.
    Returns (g, x, y) such that ax + by = g = gcd(a, b).
    """
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b // a, b % a
        m, n = x - u * q, y - v * q
        b, a, x, y, u, v = a, r, u, v, m, n
    return b, x, y

def mmi(a, m):
    """
    Calculates the multiplicative inverse of a modulo m, or raises a
    ValueError if a is not prime relative to m.
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError('%d is not prime relative to %d!' % (a, m))
    return x % m
