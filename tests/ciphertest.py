#!/usr/bin/env python

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import goldbug

class PolybiusTest(unittest.TestCase):
    def test_polybius(self):
        p = goldbug.cipher.Polybius('')
        self.assertEqual(p[(0, 0)], 'a')
        self.assertEqual(p[(0, 1)], 'b')
        self.assertEqual(p[(1, 0)], 'f')
        self.assertEqual(p[(4, 4)], 'z')

        self.assertEqual(p['a'], (0, 0))
        self.assertEqual(p['b'], (0, 1))
        self.assertEqual(p['f'], (1, 0))
        self.assertEqual(p['z'], (4, 4))

        p = goldbug.cipher.Polybius('keyword')
        self.assertEqual(p[(0, 0)], 'k')
        self.assertEqual(p['e'], (0, 1))

        p = goldbug.cipher.Polybius('', 'abcd')
        self.assertEqual(p[(0, 0)], 'a')
        self.assertEqual(p[(0, 1)], 'b')
        self.assertEqual(p['c'], (1, 0))
        self.assertEqual(p['d'], (1, 1))

    def test_polybius_str(self):
        p = goldbug.cipher.Polybius('', 'abcd')
        self.assertEqual(str(p), 'a b\nc d')

        p = goldbug.cipher.Polybius('d', 'd')
        self.assertEqual(str(p), 'd')

    def test_polybius_bad(self):
        self.assertRaises(ValueError, goldbug.cipher.Polybius, '', 'ab')
        self.assertRaises(ValueError, goldbug.cipher.Polybius, '.')
        self.assertRaises(ValueError, goldbug.cipher.Polybius, '', 'abcc')

        p = goldbug.cipher.Polybius('key')
        self.assertRaises(KeyError, p.__getitem__, '!')
        self.assertRaises(KeyError, p.__getitem__, (6, 6))

class AtbashTest(unittest.TestCase):
    def test_atbash_encryption(self):
        cipher = goldbug.cipher.Atbash()
        self.assertEqual(cipher.encrypt('test'), 'gvhg')
        self.assertEqual(cipher.encrypt('CaSepReSeRvE'), 'XzHvkIvHvIeV')
        self.assertEqual(cipher.encrypt('.#~'), '.#~')

        cipher = goldbug.cipher.Atbash('abc')
        self.assertEqual(cipher.encrypt('abc'), 'cba')
        self.assertEqual(cipher.encrypt('cabvc'), 'acbva')

        cipher = goldbug.cipher.Atbash('abcdefghijklmnopqrstuvwxyz'
                                       'zyxwvutsrqponmlkjihgfedcba')
        self.assertEqual(cipher.encrypt('identity'), 'identity')

    def test_atbash_invariants(self):
        cipher = goldbug.cipher.Atbash()
        self.assertEqual(cipher.encrypt('test'), cipher.decrypt('test'))
        self.assertEqual(cipher.encrypt(cipher.encrypt('test')), 'test')

class CaesarTest(unittest.TestCase):
    def test_caesar_encryption(self):
        cipher = goldbug.cipher.Caesar(3)
        self.assertEqual(cipher.encrypt('test'), 'whvw')

        cipher = goldbug.cipher.Caesar(14)
        self.assertEqual(cipher.encrypt('CaSepReSeRvE'), 'QoGsdFsGsFjS')

        cipher = goldbug.cipher.Caesar(6)
        self.assertEqual(cipher.encrypt('.#~'), '.#~')

        cipher = goldbug.cipher.Caesar(0)
        self.assertEqual(cipher.encrypt('identity'), 'identity')

    def test_caesar_decryption(self):
        cipher = goldbug.cipher.Caesar(3)
        self.assertEqual(cipher.decrypt('whvw'), 'test')

        cipher = goldbug.cipher.Caesar(14)
        self.assertEqual(cipher.decrypt('QoGsdFsGsFjS'), 'CaSepReSeRvE')

        cipher = goldbug.cipher.Caesar(6)
        self.assertEqual(cipher.decrypt('.#~'), '.#~')

        cipher = goldbug.cipher.Caesar(0)
        self.assertEqual(cipher.decrypt('identity'), 'identity')

    def test_caesar_invariants(self):
        self.assertEqual(goldbug.cipher.Caesar(13).encrypt('something'),
                         goldbug.cipher.Caesar(13).decrypt('something'))

        self.assertEqual(goldbug.cipher.Caesar(10).encrypt('something'),
                         goldbug.cipher.Caesar(16).decrypt('something'))

    def test_caesar_badkeys(self):
        self.assertEqual(goldbug.cipher.Caesar(4).encrypt('test'),
                         goldbug.cipher.Caesar(-22).encrypt('test'))

        self.assertRaises(ValueError, goldbug.cipher.Caesar, 'notakey')

class KeywordTest(unittest.TestCase):
    def test_keyword_encryption(self):
        cipher = goldbug.cipher.Keyword('kryptos')
        self.assertEqual(cipher.encrypt('test'), 'ntmn')

        cipher = goldbug.cipher.Keyword('secret')
        self.assertEqual(cipher.encrypt('CaSepReSeRvE'), 'CsPtmOtPtOvT')

        cipher = goldbug.cipher.Keyword('hush')
        self.assertEqual(cipher.encrypt('.#~'), '.#~')

    def test_keyword_decryption(self):
        cipher = goldbug.cipher.Keyword('kryptos')
        self.assertEqual(cipher.decrypt('ntmn'), 'test')

        cipher = goldbug.cipher.Keyword('secret')
        self.assertEqual(cipher.decrypt('CsPtmOtPtOvT'), 'CaSepReSeRvE')

        cipher = goldbug.cipher.Keyword('hush')
        self.assertEqual(cipher.decrypt('.#~'), '.#~')

    def test_keyword_invariants(self):
        self.assertEqual(goldbug.cipher.Keyword('kryptos').encrypt('test'),
                         goldbug.cipher.Keyword('kryptos' * 3).encrypt('test'))

        key1 = 'dblkhjrevscmazyqipuwofgxtn'
        key2 = 'mbkahvweqfdclzurpgjysitxon'
        self.assertEqual(goldbug.cipher.Keyword(key1).encrypt('test'),
                         goldbug.cipher.Keyword(key2).decrypt('test'))
        self.assertEqual(goldbug.cipher.Keyword(key1).decrypt('test'),
                         goldbug.cipher.Keyword(key2).encrypt('test'))

        self.assertEqual(goldbug.cipher.Keyword('').encrypt('test'), 'test')
        self.assertEqual(goldbug.cipher.Keyword('abc').encrypt('test'), 'test')

    def test_keyword_badkeys(self):
        cipher = goldbug.cipher.Keyword('.#;@')
        self.assertEqual(cipher.encrypt('ddbabcbc'), '@@#.#;#;')

class PlayfairTest(unittest.TestCase):
    def test_playfair_encryption(self):
        cipher = goldbug.cipher.Playfair('playfair example')
        self.assertEqual(cipher.encrypt('Hide the gold in the tree stump'),
                         'bmodzbxdnabekudmuixmmouvif')

    def test_playfair_decryption(self):
        cipher = goldbug.cipher.Playfair('playfair example')
        self.assertEqual(cipher.decrypt('bmodzbxdnabekudmuixmmouvif'),
                         'hidethegoldinthetrexestump')

    def test_playfair_token(self):
        tokenise = lambda c, s: ''.join(a + b for (a, b)
                                        in c._Playfair__plain_pairs(s))

        cipher = goldbug.cipher.Playfair('')
        self.assertEqual(tokenise(cipher, ''), '')
        self.assertEqual(tokenise(cipher, 'e'), 'ez')
        self.assertEqual(tokenise(cipher, 'ee'), 'exez')
        self.assertEqual(tokenise(cipher, 'eee'), 'exexez')
        self.assertEqual(tokenise(cipher, 'test'), 'test')
        self.assertEqual(tokenise(cipher, 'tqjt'), 'tqit')
        self.assertEqual(tokenise(cipher, 'xxxxx'), 'xz')

        cipher = goldbug.cipher.Playfair('', omitted={'q': ''},
                                         breaker='a', padding='b')
        self.assertEqual(tokenise(cipher, 'e'), 'eb')
        self.assertEqual(tokenise(cipher, 'ee'), 'eaeb')
        self.assertEqual(tokenise(cipher, 'test'), 'test')
        self.assertEqual(tokenise(cipher, 'tqjt'), 'tjtb')

        self.assertRaises(ValueError, list,
                          cipher._Playfair__cipher_pairs('y'))

    def test_playfair_bad(self):
        self.assertRaises(ValueError, goldbug.cipher.Playfair, '', breaker='.')
        self.assertRaises(ValueError, goldbug.cipher.Playfair, '', padding='.')
        self.assertRaises(ValueError, goldbug.cipher.Playfair, '', omitted='.')
        self.assertRaises(ValueError, goldbug.cipher.Playfair, '',
                          omitted={'.': 'a'})
        self.assertRaises(ValueError, goldbug.cipher.Playfair, '',
                          omitted={'a': '.'})

class Rot13Test(unittest.TestCase):
    def test_rot13_encryption(self):
        cipher = goldbug.cipher.Rot13()
        self.assertEqual(cipher.encrypt('test'), 'grfg')
        self.assertEqual(cipher.encrypt('CaSepReSeRvE'), 'PnFrcErFrEiR')
        self.assertEqual(cipher.encrypt('.#~'), '.#~')

    def test_rot13_invariants(self):
        cipher = goldbug.cipher.Rot13()
        self.assertEqual(cipher.encrypt('test'), cipher.decrypt('test'))
        self.assertEqual(cipher.encrypt(cipher.encrypt('test')), 'test')

class Column(unittest.TestCase):
    def test_column_encryption(self):
        cipher = goldbug.cipher.Column('german')
        self.assertEqual(cipher.encrypt('defendtheeastwallofthecastle'),
                         'nalcxehwttdttfseeleedsoaxfeahl')

        cipher = goldbug.cipher.Column('cipher', 'y')
        self.assertEqual(cipher.encrypt('thisisanexample'),
                         'tapiaysxyhnlieesmy')

        cipher = goldbug.cipher.Column('x')
        self.assertEqual(cipher.encrypt('something'), 'something')

    def test_column_decryption(self):
        cipher = goldbug.cipher.Column('german')
        self.assertEqual(cipher.decrypt('nalcxehwttdttfseeleedsoaxfeahl'),
                         'defendtheeastwallofthecastle')

        cipher = goldbug.cipher.Column('cipher', 'y')
        self.assertEqual(cipher.decrypt('tapiaysxyhnlieesmy'),
                         'thisisanexample')

        cipher = goldbug.cipher.Column('y')
        self.assertEqual(cipher.decrypt('y'), 'y')

    def test_column_bad(self):
        self.assertRaises(ValueError, goldbug.cipher.Column, '')
        self.assertRaises(ValueError, goldbug.cipher.Column, 'aa')
        self.assertRaises(ValueError, goldbug.cipher.Column, 'abc', '')
        self.assertRaises(ValueError, goldbug.cipher.Column, 'abc', 'xy')

        cipher = goldbug.cipher.Column('abc')
        self.assertRaises(ValueError, cipher.decrypt, 'abcd')

if __name__ == '__main__':
    unittest.main()
