#!/usr/bin/env python

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import goldbug

class MMITest(unittest.TestCase):
    def test_egcd(self):
        self.assertEqual(goldbug.util.egcd(120, 23), (1, -9, 47))
        self.assertEqual(goldbug.util.egcd(81, 57), (3, -7, 10))

    def test_mmi(self):
        self.assertEqual(goldbug.util.mmi(1, 1), 0)
        self.assertEqual(goldbug.util.mmi(5, 26), 21)

        self.assertRaises(ValueError, goldbug.util.mmi, 2, 4)

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

class PolybiusTest(unittest.TestCase):
    def test_polybius(self):
        p = goldbug.util.Polybius('')
        self.assertEqual(p[(0, 0)], 'a')
        self.assertEqual(p[(0, 1)], 'b')
        self.assertEqual(p[(1, 0)], 'f')
        self.assertEqual(p[(4, 4)], 'z')

        self.assertEqual(p['a'], (0, 0))
        self.assertEqual(p['b'], (0, 1))
        self.assertEqual(p['f'], (1, 0))
        self.assertEqual(p['z'], (4, 4))

        p = goldbug.util.Polybius('keyword')
        self.assertEqual(p[(0, 0)], 'k')
        self.assertEqual(p['e'], (0, 1))

        p = goldbug.util.Polybius('', 'abcd')
        self.assertEqual(p[(0, 0)], 'a')
        self.assertEqual(p[(0, 1)], 'b')
        self.assertEqual(p['c'], (1, 0))
        self.assertEqual(p['d'], (1, 1))

        p = goldbug.util.Polybius('', 'abcdefghijklmnopqrstuvwxyz.', 3)
        self.assertEqual(p[0, 0, 0], 'a')
        self.assertEqual(p[2, 2, 2], '.')
        self.assertEqual(p['b'], (0, 0, 1))
        self.assertEqual(p['z'], (2, 2, 1))

        p = goldbug.util.Polybius('', '.', 1)
        self.assertEqual(p[(0,)], '.')
        self.assertEqual(p['.'], (0,))

    def test_polybius_str(self):
        p = goldbug.util.Polybius('', 'abcd')
        self.assertEqual(str(p), 'a b\nc d')

        p = goldbug.util.Polybius('d', 'd')
        self.assertEqual(str(p), 'd')

        p = goldbug.util.Polybius('', '.', 1)
        self.assertEqual(str(p), '.')

        p = goldbug.util.Polybius('', 'abcdefghijklmnopqrstuvwxyz.', 3)
        self.assertEqual(str(p), repr(p))

    def test_polybius_bad(self):
        self.assertRaises(ValueError, goldbug.util.Polybius, '', 'ab')
        self.assertRaises(ValueError, goldbug.util.Polybius, '.')
        self.assertRaises(ValueError, goldbug.util.Polybius, '', 'abcc')

        p = goldbug.util.Polybius('key')
        self.assertRaises(KeyError, p.__getitem__, '!')
        self.assertRaises(KeyError, p.__getitem__, (6, 6))
        self.assertRaises(OverflowError, p._Polybius__index_to_coordinate, 25)

        self.assertRaises(ValueError, goldbug.util.Polybius, '', dimensions=0)
        self.assertRaises(ValueError, goldbug.util.Polybius, '', dimensions=-1)
        self.assertRaises(ValueError, goldbug.util.Polybius, '', 'abcd', 3)

    def test_polybius_misc(self):
        p = goldbug.util.Polybius('key')
        self.assertEqual(p._Polybius__index_to_coordinate(0), (0, 0))
        self.assertEqual(p._Polybius__index_to_coordinate(1), (0, 1))
        self.assertEqual(p._Polybius__index_to_coordinate(2), (0, 2))
        self.assertEqual(p._Polybius__index_to_coordinate(5), (1, 0))
        self.assertEqual(p._Polybius__index_to_coordinate(24), (4, 4))

        p = goldbug.util.Polybius('', 'abcdefghijklmnopqrstuvwxyz.', 3)
        self.assertEqual(p._Polybius__index_to_coordinate(0), (0, 0, 0))
        self.assertEqual(p._Polybius__index_to_coordinate(1), (0, 0, 1))
        self.assertEqual(p._Polybius__index_to_coordinate(2), (0, 0, 2))
        self.assertEqual(p._Polybius__index_to_coordinate(3), (0, 1, 0))
        self.assertEqual(p._Polybius__index_to_coordinate(9), (1, 0, 0))
        self.assertEqual(p._Polybius__index_to_coordinate(26), (2, 2, 2))

        p = goldbug.util.Polybius('', '.', 1)
        self.assertEqual(p._Polybius__index_to_coordinate(0), (0,))

class TabulaRectaTest(unittest.TestCase):
    def test_tabula(self):
        tabula = goldbug.util.TabulaRecta()
        self.assertEqual(tabula['a', 'a'], 'a')
        self.assertEqual(tabula['a', 'b'], 'b')
        self.assertEqual(tabula['b', 'a'], 'b')
        self.assertEqual(tabula['k', 'o'], 'y')

        tabula = goldbug.util.TabulaRecta(reverse=True)
        self.assertEqual(tabula['a', 'a'], 'a')
        self.assertEqual(tabula['b', 'b'], 'a')
        self.assertEqual(tabula['a', 'b'], 'z')
        self.assertEqual(tabula['y', 'o'], 'k')

        tabula = goldbug.util.TabulaRecta('abcd')
        for a in 'abcd':
            for b in 'abcd':
                self.assertEqual(tabula[a, b], tabula[b, a])

    def test_tabula_bad(self):
        self.assertRaises(ValueError, goldbug.util.TabulaRecta, 'abcda')

    def test_tabula_misc(self):
        self.assertEqual(repr(goldbug.util.TabulaRecta()),
                         "TabulaRecta('abcdefghijklmnopqrstuvwxyz')")
        self.assertEqual(repr(goldbug.util.TabulaRecta('abc', True)),
                         "TabulaRecta('abc', reverse=True)")

class TextgenTest(unittest.TestCase):
    def test_textgen(self):
        self.assertEqual(list(goldbug.util.textgen('abcd', 0, 2)),
                         ['', 'a', 'b', 'c', 'd',
                          'aa', 'ab', 'ac', 'ad',
                          'ba', 'bb', 'bc', 'bd',
                          'ca', 'cb', 'cc', 'cd',
                          'da', 'db', 'dc', 'dd'])
        self.assertEqual(list(goldbug.util.textgen('ba', 3, 3)),
                         ['bbb', 'bba', 'bab', 'baa',
                          'abb', 'aba', 'aab', 'aaa'])
        self.assertEqual(len(list(goldbug.util.textgen('1234', 8, 8))), 4 ** 8)

    def test_types(self):
        self.assertEqual(type(next(goldbug.util.textgen('abc'))), type('abc'))
        if hasattr('', 'decode'):
            # Python 2
            self.assertTrue(isinstance(
                next(goldbug.util.textgen('abcd'.decode('utf8'))),
                unicode
            ))
        else:
            # Python 3
            self.assertRaises(TypeError, next,
                              goldbug.util.textgen('abcd'.encode('utf8')))

class RandomDictTest(unittest.TestCase):
    def test_randomdict(self):
        d = goldbug.util.RandomDict({'a': [1, 2, 3], 'b': [4, 5], 'c': [6]})
        self.assertTrue(d['a'] in (1, 2, 3))
        self.assertTrue(d['b'] in (4, 5))
        self.assertEqual(d['c'], 6)

        d = goldbug.util.RandomDict(a="abc", b="de", c="fghi", d="j")
        a_items = [item[1] for item in d.items() if item[0] == 'a']
        self.assertEqual(sorted(a_items), ['a', 'b', 'c'])

class NumberwordTest(unittest.TestCase):
    def test_numberword(self):
        self.assertEqual(goldbug.util.numberword(0), 'zero')
        self.assertEqual(goldbug.util.numberword(1), 'one')
        self.assertEqual(goldbug.util.numberword(2), 'two')
        self.assertEqual(goldbug.util.numberword(10), 'ten')
        self.assertEqual(goldbug.util.numberword(11), 'eleven')
        self.assertEqual(goldbug.util.numberword(21), 'twentyone')
        self.assertEqual(goldbug.util.numberword(100), 'onehundred')
        self.assertEqual(goldbug.util.numberword(101), 'onehundredone')
        self.assertEqual(goldbug.util.numberword(102), 'onehundredtwo')
        self.assertEqual(goldbug.util.numberword(110), 'onehundredten')
        self.assertEqual(goldbug.util.numberword(111), 'onehundredeleven')
        self.assertEqual(goldbug.util.numberword(120), 'onehundredtwenty')
        self.assertEqual(goldbug.util.numberword(1001), 'onethousandone')
        self.assertEqual(goldbug.util.numberword(1101),
                         'onethousandonehundredone')
        self.assertEqual(goldbug.util.numberword(1111),
                         'onethousandonehundredeleven')
        self.assertEqual(goldbug.util.numberword(123456),
                         'onehundredtwentythreethousandfourhundredfiftysix')
        self.assertEqual(goldbug.util.numberword(1000000), 'onemillion')
        self.assertEqual(goldbug.util.numberword(123456789),
                         'onehundredtwentythreemillion'
                         'fourhundredfiftysixthousand'
                         'sevenhundredeightynine')

        self.assertEqual(goldbug.util.numberword(-1), 'negativeone')
        self.assertEqual(goldbug.util.numberword(-1000), 'negativeonethousand')

    def test_numberword_scales(self):
        self.assertEqual(goldbug.util.numberword(1000000),
                         goldbug.util.numberword(1000000, False))
        self.assertEqual(goldbug.util.numberword(1000000001),
                         'onebillionone')
        self.assertEqual(goldbug.util.numberword(1000000001, False),
                         'onemilliardone')

    def test_numberword_bad(self):
        self.assertRaises(TypeError, goldbug.util.numberword, None)
        self.assertRaises(ValueError, goldbug.util.numberword, 'test')
        self.assertRaises(ValueError, goldbug.util.numberword, float('nan'))
        self.assertRaises(OverflowError, goldbug.util.numberword, float('inf'))

if __name__ == '__main__':
    unittest.main()
