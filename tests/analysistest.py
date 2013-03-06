#!/usr/bin/env python

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import goldbug

class FreqAnalTest(unittest.TestCase):
    def test_freqanal(self):
        self.assertEqual(goldbug.analysis.frequency_analysis("mississipi", 1),
                         {'m': 1. / 10, 'i': 4. / 10,
                          's': 4. / 10, 'p': 1. / 10})
        self.assertEqual(goldbug.analysis.frequency_analysis("mississipi", 2),
                         {'mi': 1. / 9, 'is': 2. / 9, 'ss': 2. / 9,
                          'si': 2. / 9, 'ip': 1. / 9, 'pi': 1. / 9})
        self.assertEqual(goldbug.analysis.frequency_analysis("mississipi", 3),
                         {'mis': 1. / 8, 'iss': 2. / 8, 'ssi': 2. / 8,
                          'sis': 1. / 8, 'sip': 1. / 8, 'ipi': 1. / 8})
        self.assertEqual(goldbug.analysis.frequency_analysis("mississipi", 9),
                         {'mississip': 1. / 2, 'ississipi': 1. / 2})
        self.assertEqual(goldbug.analysis.frequency_analysis("mississipi", 10),
                         {'mississipi': 1})
        self.assertEqual(goldbug.analysis.frequency_analysis("mississipi", 11),
                         {})

class Chi2Test(unittest.TestCase):
    def test_chi2(self):
        self.assertEqual(goldbug.analysis.chi2('aaa', {'a': 1}), 0.0)
        self.assertEqual(goldbug.analysis.chi2('aaa', {'a': 0}), float('inf'))

class ICTest(unittest.TestCase):
    def test_ic(self):
        self.assertEqual(goldbug.analysis.ic('abcdefghijklmnopqrstuvwxyz'), 0.0)
        self.assertAlmostEqual(goldbug.analysis.ic('something or other'),
                               1.5166667)
        self.assertRaises(ValueError, goldbug.analysis.ic, '')

if __name__ == '__main__':
    unittest.main()
