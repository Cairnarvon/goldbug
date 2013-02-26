#!/usr/bin/env python

import functools
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from goldbug.freq import *
import goldbug.freq


langs = [globals()[lang] for lang in goldbug.freq.__all__]


class FreqTest(unittest.TestCase):
    def runTest(self):
        for lang in langs:
            self.lang_test(lang)

    def lang_test(self, lang):
        self.assertTrue(hasattr(lang, 'unigram'),
                        '%s does not have a unigram table!' % lang.__name__)
        self.assertTrue(hasattr(lang, 'bigram'),
                        '%s does not have a bigram table!' % lang.__name__)

        for n, gram in enumerate(('notagram',
                                  'unigram',
                                  'bigram',
                                  'trigram',
                                  'quadgram')):
            if hasattr(lang, gram):
                for k, v in getattr(lang, gram).items():
                    msg = '%s: %s: %%s' % (lang.__name__, gram)
                    self.assertEqual(len(k), n,
                                     msg % ('len(%r) != %d' % (k, n)))
                    self.assertTrue(isinstance(v, float),
                                    msg % ('(%r) %r is not a float' % (k, v)))


if __name__ == '__main__':
    unittest.main()
