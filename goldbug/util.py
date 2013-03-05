#!/usr/bin/env python 

"""
Utilities for studying and breaking classical ciphers.
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

def frequency_analysis(text, ngram=1):
    """
    Generates an n-gram frequency table from a source text.
    """
    freqs, total = collections.defaultdict(int), 0
    for i in range(len(text) - ngram + 1):
        freqs[text[i:i + ngram]] += 1
        total += 1
    for gram in freqs:
        freqs[gram] /= float(total)
    return dict(freqs)

def chi2(text, freqs):
    """
    Performs Pearson's chi-squared test on a potential plaintext with respect
    to a given frequency table. Lower numbers are better.
    freqs should be a table from goldbug.freq.*; for instance, to perform the
    test with respect to English unigrams, use goldbug.freq.english.unigram.
    """
    acc = 0
    for c in freqs:
        e_i = freqs[c] * len(text) / len(c) # Expected incidence
        c_i = text.count(c)                 # Observed incidence
        if e_i == 0.0 and c_i == 0:
            continue
        elif e_i == 0.0:
            acc += float('inf')
        else:
            acc += (c_i - e_i)**2 / e_i
    return acc

def ic(text, alphabet=string.ascii_lowercase):
    """
    Calculates the monographic index of coincidence for a given piece of text.
    """
    text = [c for c in text if c in alphabet]
    if len(text) < 2:
        raise ValueError('Text is too short!')
    ic = 0
    for c in alphabet:
        fi = text.count(c)
        ic += fi * (fi - 1)
    return ic / (len(text) * (len(text) - 1) / float(len(alphabet)))

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
