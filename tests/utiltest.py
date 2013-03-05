#!/usr/bin/env python

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import goldbug

class FreqAnalTest(unittest.TestCase):
    def test_freqanal(self):
        self.assertEqual(goldbug.util.frequency_analysis("mississipi", 1),
                         {'m': 1. / 10, 'i': 4. / 10,
                          's': 4. / 10, 'p': 1. / 10})
        self.assertEqual(goldbug.util.frequency_analysis("mississipi", 2),
                         {'mi': 1. / 9, 'is': 2. / 9, 'ss': 2. / 9,
                          'si': 2. / 9, 'ip': 1. / 9, 'pi': 1. / 9})
        self.assertEqual(goldbug.util.frequency_analysis("mississipi", 3),
                         {'mis': 1. / 8, 'iss': 2. / 8, 'ssi': 2. / 8,
                          'sis': 1. / 8, 'sip': 1. / 8, 'ipi': 1. / 8})
        self.assertEqual(goldbug.util.frequency_analysis("mississipi", 9),
                         {'mississip': 1. / 2, 'ississipi': 1. / 2})
        self.assertEqual(goldbug.util.frequency_analysis("mississipi", 10),
                         {'mississipi': 1})
        self.assertEqual(goldbug.util.frequency_analysis("mississipi", 11),
                         {})

class Chi2Test(unittest.TestCase):
    def test_chi2(self):
        self.assertEqual(goldbug.util.chi2('aaa', {'a': 1}), 0.0)
        self.assertEqual(goldbug.util.chi2('aaa', {'a': 0}), float('inf'))

class MMITest(unittest.TestCase):
    def test_egcd(self):
        self.assertEqual(goldbug.util.egcd(120, 23), (1, -9, 47))
        self.assertEqual(goldbug.util.egcd(81, 57), (3, -7, 10))

    def test_mmi(self):
        self.assertEqual(goldbug.util.mmi(1, 1), 0)
        self.assertEqual(goldbug.util.mmi(5, 26), 21)

        self.assertRaises(ValueError, goldbug.util.mmi, 2, 4)

class ICTest(unittest.TestCase):
    def test_ic(self):
        self.assertEqual(goldbug.util.ic('abcdefghijklmnopqrstuvwxyz'), 0.0)
        self.assertAlmostEqual(goldbug.util.ic('something or other'), 1.5166667)
        self.assertRaises(ValueError, goldbug.util.ic, '')

class MatrixTest(unittest.TestCase):
    def test_matrix_constructor(self):
        self.assertRaises(ValueError, goldbug.util.Matrix, ((1, 0), (1,)))
        self.assertRaises(IndexError, goldbug.util.Matrix, [])
        self.assertRaises(IndexError, goldbug.util.Matrix, size=(1,))
        self.assertRaises(ValueError, goldbug.util.Matrix, size=-1)
        self.assertRaises(ValueError, goldbug.util.Matrix, size=(14, -1))
        self.assertRaises(ValueError, goldbug.util.Matrix, ((0, 1), (1, 0)), 4)

        goldbug.util.Matrix(((1, 0), (0, 1)))
        goldbug.util.Matrix(size=4)
        goldbug.util.Matrix(size=(2, 3))

    def test_matrix_getset(self):
        m1 = goldbug.util.Matrix(((1, 2), (3, 4)))
        self.assertEqual(m1[0, 0], 1)
        self.assertEqual(m1[1, 1], 4)

        m1[0, 1] = 5
        self.assertEqual(m1[0, 1], 5)

        m2 = goldbug.util.Matrix(m1.values)
        m1[0, 1] = 6
        self.assertEqual(m1[0, 1], 6)
        self.assertEqual(m2[0, 1], 5)

        self.assertEqual(m1.row(0), [1, 6])
        self.assertEqual(m1.col(0), [1, 3])

    def test_matrix_arithmetic(self):
        m1 = goldbug.util.Matrix(((0, 1), (2, 3)))
        m2 = goldbug.util.Matrix(((4, 5), (6, 7)))
        m3 = m1 + m2
        m4 = m2 + m1
        self.assertEqual(m3, m4)
        self.assertEqual(m3.values, [[4, 6], [8, 10]])

        m1 += 3
        self.assertEqual(m1.values, [[3, 4], [5, 6]])

        m = goldbug.util.Matrix(((0, 1), (2, 3)))
        m *= 2
        self.assertEqual(m.values, [[0, 2], [4, 6]])

        m1 = goldbug.util.Matrix(((1, 0, -2), (0, 3, -1)))
        m2 = goldbug.util.Matrix(((0, 3), (-2, -1), (0, 4)))
        m3 = m1 * m2
        self.assertEqual(m3.values, [[0, -5], [-6, -7]])
        self.assertRaises(ValueError, m1.__mul__, m1)

        m = goldbug.util.Matrix(((1, 2), (3, 4)))
        m1 = m * m
        self.assertEqual(m1.values, [[7, 10], [15, 22]])
        m1 *= m
        self.assertEqual(m1.values, [[37, 54], [81, 118]])

        self.assertEqual(m ** 3, m1)

        m1 %= 3
        self.assertEqual(m1.values, [[1, 0], [0, 1]])

    def test_matrix_invert(self):
        m = pow(goldbug.util.Matrix(((3, 3), (2, 5))), -1, 26)
        self.assertEqual(m.values, [[15, 17], [20, 9]])

        m = pow(goldbug.util.Matrix(((1, 2), (3, 4))), -1, 7)
        self.assertEqual(m.values, [[5, 1], [5, 3]])

        m = goldbug.util.Matrix(((1, 2), (3, 4)))
        self.assertRaises(NotImplementedError, pow, m, -1)
        self.assertRaises(ValueError, pow, m, -1, 2)

    def test_matrix_misc(self):
        self.assertEqual(str(goldbug.util.Matrix(((1, 2), (3, 4)))),
                         '1 2\n3 4')
        self.assertEqual(str(goldbug.util.Matrix(size=3)),
                         '0 0 0\n0 0 0\n0 0 0')
        self.assertEqual(str(goldbug.util.Matrix(((1, 1000), (1, 1)))),
                         '   1 1000\n   1    1')
        self.assertEqual(repr(goldbug.util.Matrix(((1, 2), (3, 4)))),
                         'Matrix([[1, 2], [3, 4]])')
        self.assertEqual(repr(goldbug.util.Matrix(size=3)),
                         'Matrix([[0, 0, 0], [0, 0, 0], [0, 0, 0]])')

if __name__ == '__main__':
    unittest.main()
