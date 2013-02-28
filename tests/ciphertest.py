#!/usr/bin/env python

import os
import string
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

        p = goldbug.cipher.Polybius('', 'abcdefghijklmnopqrstuvwxyz.', 3)
        self.assertEqual(p[0, 0, 0], 'a')
        self.assertEqual(p[2, 2, 2], '.')
        self.assertEqual(p['b'], (0, 0, 1))
        self.assertEqual(p['z'], (2, 2, 1))

        p = goldbug.cipher.Polybius('', '.', 1)
        self.assertEqual(p[(0,)], '.')
        self.assertEqual(p['.'], (0,))

    def test_polybius_str(self):
        p = goldbug.cipher.Polybius('', 'abcd')
        self.assertEqual(str(p), 'a b\nc d')

        p = goldbug.cipher.Polybius('d', 'd')
        self.assertEqual(str(p), 'd')

        p = goldbug.cipher.Polybius('', '.', 1)
        self.assertEqual(str(p), '.')

        p = goldbug.cipher.Polybius('', 'abcdefghijklmnopqrstuvwxyz.', 3)
        self.assertEqual(str(p), repr(p))

    def test_polybius_bad(self):
        self.assertRaises(ValueError, goldbug.cipher.Polybius, '', 'ab')
        self.assertRaises(ValueError, goldbug.cipher.Polybius, '.')
        self.assertRaises(ValueError, goldbug.cipher.Polybius, '', 'abcc')

        p = goldbug.cipher.Polybius('key')
        self.assertRaises(KeyError, p.__getitem__, '!')
        self.assertRaises(KeyError, p.__getitem__, (6, 6))
        self.assertRaises(OverflowError, p._Polybius__index_to_coordinate, 25)

        self.assertRaises(ValueError, goldbug.cipher.Polybius, '', dimensions=0)
        self.assertRaises(ValueError, goldbug.cipher.Polybius, '', dimensions=-1)
        self.assertRaises(ValueError, goldbug.cipher.Polybius, '', 'abcd', 3)

    def test_polybius_misc(self):
        p = goldbug.cipher.Polybius('key')
        self.assertEqual(p._Polybius__index_to_coordinate(0), (0, 0))
        self.assertEqual(p._Polybius__index_to_coordinate(1), (0, 1))
        self.assertEqual(p._Polybius__index_to_coordinate(2), (0, 2))
        self.assertEqual(p._Polybius__index_to_coordinate(5), (1, 0))
        self.assertEqual(p._Polybius__index_to_coordinate(24), (4, 4))

        p = goldbug.cipher.Polybius('', 'abcdefghijklmnopqrstuvwxyz.', 3)
        self.assertEqual(p._Polybius__index_to_coordinate(0), (0, 0, 0))
        self.assertEqual(p._Polybius__index_to_coordinate(1), (0, 0, 1))
        self.assertEqual(p._Polybius__index_to_coordinate(2), (0, 0, 2))
        self.assertEqual(p._Polybius__index_to_coordinate(3), (0, 1, 0))
        self.assertEqual(p._Polybius__index_to_coordinate(9), (1, 0, 0))
        self.assertEqual(p._Polybius__index_to_coordinate(26), (2, 2, 2))

        p = goldbug.cipher.Polybius('', '.', 1)
        self.assertEqual(p._Polybius__index_to_coordinate(0), (0,))


# Substitution ciphers

class AffineTest(unittest.TestCase):
    def test_affine_encryption(self):
        cipher = goldbug.cipher.Affine((5, 7))
        self.assertEqual(cipher.encrypt('Defend the east wall of the castle'),
                         'Wbgbuw yqb bhty nhkk zg yqb rhtykb')

        cipher = goldbug.cipher.Affine((1, 0))
        self.assertEqual(cipher.encrypt('Something something.'),
                         'Something something.')

        cipher = goldbug.cipher.Affine((3, 1), 'abCde')
        self.assertEqual(cipher.encrypt('Adbaes'), 'Baebds')

    def test_affine_decryption(self):
        cipher = goldbug.cipher.Affine((5, 7))
        self.assertEqual(cipher.decrypt('Wbgbuw yqb bhty nhkk zg yqb rhtykb'),
                         'Defend the east wall of the castle')

        cipher = goldbug.cipher.Affine((1, 0))
        self.assertEqual(cipher.decrypt('Something something.'),
                         'Something something.')

        cipher = goldbug.cipher.Affine((3, 1), 'abCde')
        self.assertEqual(cipher.decrypt('Baebds'), 'Adbaes')

    def test_affine_bad(self):
        self.assertRaises(ValueError, goldbug.cipher.Affine, (2, 4))

    def test_affine_misc(self):
        self.assertEqual(repr(goldbug.cipher.Affine((5, 7))),
                         "Affine((5, 7), alphabet='abcdefghijklmnopqrstuvwxyz')")
        self.assertEqual(repr(goldbug.cipher.Affine((3, 1), 'abCde')),
                         "Affine((3, 1), alphabet='abcde')")

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

    def test_atbash_misc(self):
        self.assertEqual(repr(goldbug.cipher.Atbash()),
                         "Atbash(alphabet='abcdefghijklmnopqrstuvwxyz')")
        self.assertEqual(repr(goldbug.cipher.Atbash('abc')),
                         "Atbash(alphabet='abc')")

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

    def test_caesar_misc(self):
        self.assertEquals(repr(goldbug.cipher.Caesar(4)), 'Caesar(4)')

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

    def test_keyword_misc(self):
        self.assertEqual(repr(goldbug.cipher.Keyword('abc')), "Keyword('abc')")

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

    def test_playfair_misc(self):
        self.assertEqual(
            repr(goldbug.cipher.Playfair('a')),
            "Playfair('a', breaker='x', padding='z', omitted={'j': 'i'})"
        )
        self.assertEqual(
            repr(goldbug.cipher.Playfair('a', 'a', 'a', {'q': ''})),
            "Playfair('a', breaker='a', padding='a', omitted={'q': ''})"
        )

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

    def test_rot13_misc(self):
        self.assertEqual(repr(goldbug.cipher.Rot13()), 'Rot13()')

class SimpleTest(unittest.TestCase):
    def test_simple_encryption(self):
        cipher = goldbug.cipher.Simple(dict(zip(string.ascii_lowercase,
                                                'sxbveqiagnuorpdfmcyhltzjkw')))
        self.assertEqual(cipher.encrypt('zyxwvutsrqponmlkjihgfedcba'),
                         'wkjztlhycmfdproungaiqevbxs')

    def test_simple_decryption(self):
        cipher = goldbug.cipher.Simple(dict(zip(string.ascii_lowercase,
                                                'sxbveqiagnuorpdfmcyhltzjkw')))

        self.assertEqual(cipher.decrypt('wkjztlhycmfdproungaiqevbxs'),
                         'zyxwvutsrqponmlkjihgfedcba')

    def test_simple_bad(self):
        self.assertRaises(TypeError, goldbug.cipher.Simple, 14)

    def test_simple_misc(self):
        self.assertEqual(repr(goldbug.cipher.Simple({'a': '!'})),
                         "Simple({'a': '!'})")


# Transposition ciphers.

class ColumnTest(unittest.TestCase):
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

    def test_column_misc(self):
        self.assertEqual(repr(goldbug.cipher.Column('cipher')),
                         "Column('cipher', pad='x')")
        self.assertEqual(repr(goldbug.cipher.Column('german', 'q')),
                         "Column('german', pad='q')")

class RailFenceTest(unittest.TestCase):
    def test_railfence_encrypt(self):
        cipher = goldbug.cipher.RailFence(3)
        self.assertEqual(cipher.encrypt('defendtheeastwallofthecastle'),
                         'dnetlhseedheswloteateftaafcl')
        self.assertEqual(cipher.encrypt('wearediscoveredfleeatonce'),
                         'wecrlteerdsoeefeaocaivden')

        cipher = goldbug.cipher.RailFence(4)
        self.assertEqual(cipher.encrypt('defendtheeastwallofthecastle'),
                         'dttfsedhswotatfneaalhcleelee')

        cipher = goldbug.cipher.RailFence(1)
        self.assertEqual(cipher.encrypt('anything'), 'anything')

        cipher = goldbug.cipher.RailFence(50)
        self.assertEqual(cipher.encrypt('tooshort'), 'tooshort')

    def test_railfence_decrypt(self):
        cipher = goldbug.cipher.RailFence(3)
        self.assertEqual(cipher.decrypt('dnetlhseedheswloteateftaafcl'),
                         'defendtheeastwallofthecastle')
        self.assertEqual(cipher.decrypt('wecrlteerdsoeefeaocaivden'),
                         'wearediscoveredfleeatonce')

        cipher = goldbug.cipher.RailFence(4)
        self.assertEqual(cipher.decrypt('dttfsedhswotatfneaalhcleelee'),
                         'defendtheeastwallofthecastle')

        cipher = goldbug.cipher.RailFence(1)
        self.assertEqual(cipher.decrypt('anything'), 'anything')

        cipher = goldbug.cipher.RailFence(50)
        self.assertEqual(cipher.decrypt('tooshort'), 'tooshort')

    def test_railfence_bad(self):
        self.assertRaises(ValueError, goldbug.cipher.RailFence, -1)
        self.assertRaises(ValueError, goldbug.cipher.RailFence, 'secret')

        cipher = goldbug.cipher.RailFence(1)
        self.assertRaises(ZeroDivisionError, cipher._RailFence__periods, 12)

    def test_railfence_misc(self):
        self.assertEqual(repr(goldbug.cipher.RailFence(4)), 'RailFence(4)')

        cipher = goldbug.cipher.RailFence(3)
        self.assertAlmostEqual(cipher._RailFence__periods(18), 4.5)
        self.assertAlmostEqual(cipher._RailFence__periods(4), 1.0)

        cipher = goldbug.cipher.RailFence(4)
        self.assertAlmostEqual(cipher._RailFence__periods(18), 3.0)
        self.assertAlmostEqual(cipher._RailFence__periods(4), 0.6666667)


# Other ciphers.

class BifidTest(unittest.TestCase):
    def test_bifid_encrypt(self):
        cipher = goldbug.cipher.Bifid('bgwkzqpndsioaxefclumthyvr')
        self.assertEqual(cipher.encrypt('fleeatonce'), 'uaeolwrins')

        poly = goldbug.cipher.Polybius('bgwkzqpndsioaxefclumthyvr')
        self.assertEqual(goldbug.cipher.Bifid(poly).encrypt('anything'),
                         cipher.encrypt('anything'))

        cipher = goldbug.cipher.Bifid('phqgmeaylnofdxkrcvszwbuti', 5)
        self.assertEqual(cipher.encrypt('defendtheeastwallofthecastle'),
                         'ffyhmkhycpliashadtrlhcchlblr')

    def test_bifid_decrypt(self):
        cipher = goldbug.cipher.Bifid('bgwkzqpndsioaxefclumthyvr')
        self.assertEqual(cipher.decrypt('uaeolwrins'), 'fleeatonce')

        poly = goldbug.cipher.Polybius('bgwkzqpndsioaxefclumthyvr')
        self.assertEqual(goldbug.cipher.Bifid(poly).decrypt('anything'),
                         cipher.decrypt('anything'))

        cipher = goldbug.cipher.Bifid('phqgmeaylnofdxkrcvszwbuti', 5)
        self.assertEqual(cipher.decrypt('ffyhmkhycpliashadtrlhcchlblr'),
                         'defendtheeastwallofthecastle')

    def test_bifid_bad(self):
        cipher = goldbug.cipher.Bifid('bgwkzqpndsioaxefclumthyvr')
        self.assertRaises(KeyError, cipher.encrypt, '!!!')
        self.assertRaises(KeyError, cipher.decrypt, '!!!')

    def test_bifid_misc(self):
        self.assertEqual(repr(goldbug.cipher.Bifid('bgwkzqpndsioaxefclumthyvr')),
                         "Bifid('bgwkzqpndsioaxefclumthyvr')")

        poly = goldbug.cipher.Polybius('bgwkzqpndsioaxefclumthyvr')
        self.assertEqual(repr(goldbug.cipher.Bifid(poly)),
                         "Bifid('bgwkzqpndsioaxefclumthyvr')")

        cipher = goldbug.cipher.Bifid('bgwkzqpndsioaxefclumthyvr', 3)
        self.assertEqual(repr(cipher), "Bifid('bgwkzqpndsioaxefclumthyvr', 3)")

class TrifidTest(unittest.TestCase):
    def test_trifid_encrypt(self):
        cipher = goldbug.cipher.Trifid('epsducvwym.zlkxnbtfgorijhaq', 5)
        self.assertEqual(cipher.encrypt('defendtheeastwallofthecastle'),
                         'suefecphsegyyjiximfofocejlrf')

        cipher = goldbug.cipher.Trifid('abcdefgh', -1)
        self.assertEqual(cipher.encrypt('abcdefgh'), 'adgdbfcf')

    def test_trifid_decrypt(self):
        cipher = goldbug.cipher.Trifid('epsducvwym.zlkxnbtfgorijhaq', 5)
        self.assertEqual(cipher.decrypt('suefecphsegyyjiximfofocejlrf'),
                         'defendtheeastwallofthecastle')

        cipher = goldbug.cipher.Trifid('abcdefgh', -1)
        self.assertEqual(cipher.decrypt('adgdbfcf'), 'abcdefgh')

    def test_trifid_bad(self):
        self.assertRaises(ValueError, goldbug.cipher.Trifid, 'ab', 3)
        self.assertRaises(ValueError, goldbug.cipher.Trifid,
                          goldbug.cipher.Polybius('', 'abcd'), 2)

        cipher = goldbug.cipher.Trifid('abcdefgh', 3)
        self.assertRaises(KeyError, cipher.decrypt, 'ijklm')

    def test_trifid_misc(self):
        self.assertEqual(repr(goldbug.cipher.Trifid('abcdefgh', 3)),
                         "Trifid('abcdefgh', 3)")
        self.assertEqual(repr(goldbug.cipher.Trifid('.', -1)),
                         "Trifid('.')")


if __name__ == '__main__':
    unittest.main()
