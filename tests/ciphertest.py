#!/usr/bin/env python

import os
import string
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import goldbug

if not hasattr(unittest, 'skipIf'):
    # skipIf was introduced in 2.7. We're only using skipIf to skip tests in
    # Python 3, though, so if skipIf isn't present, we'll just run them
    # unconditionally.
    def skipIf(condition, reason):
        return lambda fn: fn
    unittest.skipIf = skipIf

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

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Affine((5, 7))
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

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

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Atbash()
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_atbash_misc(self):
        self.assertEqual(repr(goldbug.cipher.Atbash()),
                         "Atbash(alphabet='abcdefghijklmnopqrstuvwxyz')")
        self.assertEqual(repr(goldbug.cipher.Atbash('abc')),
                         "Atbash(alphabet='abc')")

class AutokeyTest(unittest.TestCase):
    def test_autokey_encryption(self):
        cipher = goldbug.cipher.Autokey('queenly')
        self.assertEqual(cipher.encrypt('attackatdawn'), 'qnxepvytwtwp')

    def test_autokey_decryption(self):
        cipher = goldbug.cipher.Autokey('queenly')
        self.assertEqual(cipher.decrypt('qnxepvytwtwp'), 'attackatdawn')

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Autokey('something')
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_autokey_misc(self):
        self.assertEqual(repr(goldbug.cipher.Autokey('queenly')),
                         "Autokey('queenly')")

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

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Caesar(14)
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_caesar_misc(self):
        self.assertEquals(repr(goldbug.cipher.Caesar(4)), 'Caesar(4)')

class Chaocipher(unittest.TestCase):
    def test_chaocipher_encryption(self):
        cipher = goldbug.cipher.Chaocipher('hxuczvamdslkpefjrigtwobnyq',
                                           'ptlnbqdeoysfavzkgjrihwxumc')
        self.assertEqual(cipher.encrypt('welldoneisbetterthanwellsaid'),
                                        'oahqhcnynxtszjrrhjbyhqksoujy')

    def test_chaocipher_decryption(self):
        cipher = goldbug.cipher.Chaocipher('hxuczvamdslkpefjrigtwobnyq',
                                           'ptlnbqdeoysfavzkgjrihwxumc')
        self.assertEqual(cipher.decrypt('oahqhcnynxtszjrrhjbyhqksoujy'),
                                        'welldoneisbetterthanwellsaid')

    def test_chaocipher_bad(self):
        self.assertRaises(ValueError, goldbug.cipher.Chaocipher,
                          'abcdefghijklmnopqrstuvwxyz',
                          'abcdefghijklmnopqrstuvwxy')
        self.assertRaises(ValueError, goldbug.cipher.Chaocipher,
                          'abcdefghijklmnopqrstuvwyyz',
                          'abcdefghijklmnopqrstuvwxyz')
        self.assertRaises(ValueError, goldbug.cipher.Chaocipher,
                          'ab', 'ab')
        self.assertRaises(ValueError, goldbug.cipher.Chaocipher,
                          'abcdefghijklm', 'nopqrstuvwxyz')

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Chaocipher('abcdefghijklmnopqrstuvwxyz',
                                           'abcdefghijklmnopqrstuvwxyz')
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_chaocipher_misc(self):
        cipher = goldbug.cipher.Chaocipher('hxuczvamdslkpefjrigtwobnyq',
                                           'ptlnbqdeoysfavzkgjrihwxumc')
        self.assertEqual(repr(cipher),
                         "Chaocipher('hxuczvamdslkpefjrigtwobnyq', "
                         "'ptlnbqdeoysfavzkgjrihwxumc')")

class FourSquareTest(unittest.TestCase):
    def test_foursquare_encryption(self):
        cipher = goldbug.cipher.FourSquare(
            (goldbug.util.Polybius('example', 'abcdefghijklmnoprstuvwxyz'),
             goldbug.util.Polybius('keyword', 'abcdefghijklmnoprstuvwxyz')),
            goldbug.util.Polybius('', 'abcdefghijklmnoprstuvwxyz')
        )
        self.assertEqual(cipher.encrypt('helpmeobiwankenobi'),
                         'fygmkyhobxmfkkkimd')

    def test_foursquare_decryption(self):
        cipher = goldbug.cipher.FourSquare(
            (goldbug.util.Polybius('example', 'abcdefghijklmnoprstuvwxyz'),
             goldbug.util.Polybius('keyword', 'abcdefghijklmnoprstuvwxyz')),
            goldbug.util.Polybius('', 'abcdefghijklmnoprstuvwxyz')
        )
        self.assertEqual(cipher.decrypt('fygmkyhobxmfkkkimd'),
                         'helpmeobiwankenobi')

    def test_foursquare_bad(self):
        p1 = goldbug.util.Polybius('secret')
        p2 = goldbug.util.Polybius('', 'abcd')
        p3 = goldbug.util.Polybius('', 'abcdefgh', dimensions=3)

        self.assertRaises(ValueError, goldbug.cipher.FourSquare, (p1, p2))
        self.assertRaises(ValueError, goldbug.cipher.FourSquare, (p1, p1), p3)
        self.assertRaises(ValueError, goldbug.cipher.FourSquare, (p1, p2), p3)

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.FourSquare((goldbug.util.Polybius('example'),
                                            goldbug.util.Polybius('key')))
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_foursquare_misc(self):
        cipher = goldbug.cipher.FourSquare((goldbug.util.Polybius('secret'),
                                            goldbug.util.Polybius('message')))
        self.assertEqual(repr(cipher),
            "FourSquare((Polybius('secret', 'abcdefghiklmnopqrstuvwxyz'), "
            "Polybius('message', 'abcdefghiklmnopqrstuvwxyz')), "
            "Polybius('', 'abcdefghiklmnopqrstuvwxyz'))")

class HillTest(unittest.TestCase):
    def test_hill_encryption(self):
        cipher = goldbug.cipher.Hill(goldbug.util.Matrix([[3, 3], [2, 5]]))
        self.assertEqual(cipher.encrypt('help'), 'hiat')

    def test_hill_decryption(self):
        cipher = goldbug.cipher.Hill(goldbug.util.Matrix([[3, 3], [2, 5]]))
        self.assertEqual(cipher.decrypt('hiat'), 'help')

    def test_hill_bad(self):
        self.assertRaises(TypeError, goldbug.cipher.Hill, 1)
        self.assertRaises(ValueError, goldbug.cipher.Hill,
                          goldbug.util.Matrix(((1, 2), (3, 4))), 'abcdd')

        cipher = goldbug.cipher.Hill(goldbug.util.Matrix([[3, 3], [2, 5]]))
        self.assertRaises(ValueError, cipher.encrypt, 'abc')
        self.assertRaises(ValueError, cipher.decrypt, 'abc')

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Hill(goldbug.util.Matrix([[3, 3], [2, 5]]))
        self.assertEqual(type(cipher.encrypt('test')), type('test'))
        self.assertEqual(type(cipher.encrypt('test'.decode('utf8'))),
                         type('test'.decode('utf8')))

    def test_hill_misc(self):
        self.assertEqual(goldbug.cipher.Hill('ddcf').key,
                         goldbug.util.Matrix([[3, 3], [2, 5]]))
        self.assertEqual(
            repr(goldbug.cipher.Hill(goldbug.util.Matrix(((3, 3), (2, 5))))),
            'Hill(Matrix([[3, 3], [2, 5]]))'
        )
        self.assertEqual(
            repr(goldbug.cipher.Hill(goldbug.util.Matrix(((1, 2), (3, 4))),
                                     'abcde')),
            "Hill(Matrix([[1, 2], [3, 4]]), alphabet='abcde')"
        )

class HomophonicTest(unittest.TestCase):
    def test_homophonic_encryption(self):
        d = goldbug.util.RandomDict({'a': '12', 'b': '34'})
        cipher = goldbug.cipher.Homophonic(d)
        self.assertTrue(cipher.encrypt('ab') in ('13', '14', '23', '24'))

    def test_homophonic_decryption(self):
        d = goldbug.util.RandomDict({'a': '12', 'b': '34'})
        cipher = goldbug.cipher.Homophonic(d)
        self.assertEqual(cipher.decrypt('13'), 'ab')
        self.assertEqual(cipher.decrypt('14'), 'ab')
        self.assertEqual(cipher.decrypt('23'), 'ab')
        self.assertEqual(cipher.decrypt('24'), 'ab')

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Homophonic(goldbug.util.RandomDict({'a': '12',
                                                                    'b': '34'}))
        self.assertEqual(type(cipher.encrypt('abab')), type('abab'))
        self.assertEqual(type(cipher.encrypt('abab'.decode('utf8'))),
                         type('abab'.decode('utf8')))

    def test_homophonic_misc(self):
        d = goldbug.util.RandomDict({'a': '12', 'b': '34'})
        self.assertEqual(repr(goldbug.cipher.Homophonic(d)),
                         'Homophonic(%r)' % d)

class KamaSutraTest(unittest.TestCase):
    def test_kamasutra_encryption(self):
        cipher = goldbug.cipher.KamaSutra('vqajflymsbckuhzdxtenorpwig')
        self.assertEqual(cipher.encrypt('More than a sex manual.'),
                         'Omsl fvdy d rlj odygde.')

    def test_kamasutra_decryption(self):
        cipher = goldbug.cipher.KamaSutra('vqajflymsbckuhzdxtenorpwig')
        self.assertEqual(cipher.decrypt('Omsl fvdy d rlj odygde.'),
                         'More than a sex manual.')

    def test_kamasutra_invariant(self):
        cipher = goldbug.cipher.KamaSutra('abcdefghijklmnopqrstuvwxyz')
        self.assertEqual(cipher.encrypt('whatever'), cipher.decrypt('whatever'))

        cipher = goldbug.cipher.KamaSutra('')
        self.assertEqual(cipher.encrypt('whatever'), 'whatever')

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.KamaSutra('abcdefghijklmnopqrstuvwxyz')
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_kamasutra_misc(self):
        self.assertEqual(repr(goldbug.cipher.KamaSutra('abcdefgh')),
                         "KamaSutra('abcdefgh')")

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

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Keyword('kryptos')
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

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

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Playfair('a')
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

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

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Rot13()
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

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
        self.assertRaises(AttributeError, goldbug.cipher.Simple, 14)

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Simple({'a': '!'})
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_simple_misc(self):
        self.assertEqual(repr(goldbug.cipher.Simple({'a': '!'})),
                         "Simple({'a': '!'})")

class TwoSquareTest(unittest.TestCase):
    def test_twosquare_encryption(self):
        cipher = goldbug.cipher.TwoSquare(
            (goldbug.util.Polybius('example', 'abcdefghijklmnoprstuvwxyz'),
             goldbug.util.Polybius('keyword', 'abcdefghijklmnoprstuvwxyz'))
        )
        self.assertEqual(cipher.encrypt('helpmeobiwankenobi'),
                         'hedlxwsdjyanhotkdg')

        cipher = goldbug.cipher.TwoSquare(
            (goldbug.util.Polybius('example', 'abcdefghijklmnoprstuvwxyz'),
             goldbug.util.Polybius('keyword', 'abcdefghijklmnoprstuvwxyz')),
            horizontal=True
        )
        self.assertEqual(cipher.encrypt('helpmeobiwankenobi'),
                         'xgnbmebpairypgeshb')

    def test_twosquare_decryption(self):
        cipher = goldbug.cipher.TwoSquare(
            (goldbug.util.Polybius('example', 'abcdefghijklmnoprstuvwxyz'),
             goldbug.util.Polybius('keyword', 'abcdefghijklmnoprstuvwxyz'))
        )
        self.assertEqual(cipher.decrypt('hedlxwsdjyanhotkdg'),
                         'helpmeobiwankenobi')

        cipher = goldbug.cipher.TwoSquare(
            (goldbug.util.Polybius('example', 'abcdefghijklmnoprstuvwxyz'),
             goldbug.util.Polybius('keyword', 'abcdefghijklmnoprstuvwxyz')),
            horizontal=True
        )
        self.assertEqual(cipher.decrypt('xgnbmebpairypgeshb'),
                         'helpmeobiwankenobi')

    def test_twosquare_invariants(self):
        squares = (goldbug.util.Polybius('example',
                                         'abcdefghijklmnoprstuvwxyz'),
                   goldbug.util.Polybius('keyword',
                                         'abcdefghijklmnoprstuvwxyz'))

        cipher = goldbug.cipher.TwoSquare(squares)
        self.assertEqual(cipher.encrypt('anything'),
                         cipher.decrypt('anything'))

        cipher = goldbug.cipher.TwoSquare(squares, True)
        self.assertEqual(cipher.encrypt('anything'),
                         cipher.decrypt('anything'))

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.TwoSquare((goldbug.util.Polybius('example'),
                                           goldbug.util.Polybius('keyword')))
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_twosquare_misc(self):
        squares = (goldbug.util.Polybius('example'),
                   goldbug.util.Polybius('keyword'))
        self.assertEqual(repr(goldbug.cipher.TwoSquare(squares)),
                         'TwoSquare(%r, horizontal=False)' % (squares,))

class VigenereTest(unittest.TestCase):
    def test_vigenere_encryption(self):
        cipher = goldbug.cipher.Vigenere('lemon')
        self.assertEqual(cipher.encrypt('attackatdawn'), 'lxfopvefrnhr')

        cipher = goldbug.cipher.Vigenere('fortification')
        self.assertEqual(cipher.encrypt('defendtheeastwallofthecastle'),
                         'iswxvibjexiggbocewkbjeviggqs')

    def test_vigenere_decryption(self):
        cipher = goldbug.cipher.Vigenere('lemon')
        self.assertEqual(cipher.decrypt('lxfopvefrnhr'), 'attackatdawn')

        cipher = goldbug.cipher.Vigenere('fortification')
        self.assertEqual(cipher.decrypt('iswxvibjexiggbocewkbjeviggqs'),
                         'defendtheeastwallofthecastle')

    def test_vigenere_bad(self):
        self.assertRaises(ValueError, goldbug.cipher.Vigenere, 'ab.')
        self.assertRaises(ValueError, goldbug.cipher.Vigenere, 'ab', '.;')

        cipher = goldbug.cipher.Vigenere('test')
        self.assertRaises(KeyError, cipher.encrypt, 'abc..def')

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Vigenere('lemon')
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_vigenere_misc(self):
        self.assertEqual(repr(goldbug.cipher.Vigenere('lemon')),
                         "Vigenere('lemon')")
        self.assertEqual(repr(goldbug.cipher.Vigenere('a', 'abcd')),
                         "Vigenere('a', alphabet='abcd')")


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

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Column('lemon')
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

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

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.RailFence(5)
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_railfence_misc(self):
        self.assertEqual(repr(goldbug.cipher.RailFence(4)), 'RailFence(4)')

        cipher = goldbug.cipher.RailFence(3)
        self.assertAlmostEqual(cipher._RailFence__periods(18), 4.5)
        self.assertAlmostEqual(cipher._RailFence__periods(4), 1.0)

        cipher = goldbug.cipher.RailFence(4)
        self.assertAlmostEqual(cipher._RailFence__periods(18), 3.0)
        self.assertAlmostEqual(cipher._RailFence__periods(4), 0.6666667)


# Other ciphers.

class BazeriesTest(unittest.TestCase):
    def test_bazeries_encrypt(self):
        cipher = goldbug.cipher.Bazeries(1973)
        self.assertEqual(cipher.encrypt('retreatatoncetheenemy'
                                        'isoutnumberingyou'),
                         'dklolopdlpppvlpryapymuaxylxkbgkmsygdpx')

        cipher = goldbug.cipher.Bazeries(81257)
        self.assertEqual(cipher.encrypt('whoeverhasmadeavoyageupthehudson'
                                        'mustrememberthekaatskillmountains'),
                         'dumtmcdsenrtemveqxmoelccrvxdmdkwx'
                         'nnmukrdkumynmbprkeepmgngekwxcrwb')

    def test_bazeries_decrypt(self):
        cipher = goldbug.cipher.Bazeries(1973)
        self.assertEqual(cipher.decrypt('dklolopdlpppvlpryapym'
                                        'uaxylxkbgkmsygdpx'),
                         'retreatatoncetheenemyisoutnumberingyou')

        cipher = goldbug.cipher.Bazeries(81257)
        self.assertEqual(cipher.decrypt('dumtmcdsenrtemveqxmoelccrvxdmdkwx'
                                        'nnmukrdkumynmbprkeepmgngekwxcrwb'),
                         'whoeverhasmadeavoyageupthehudson'
                         'mustrememberthekaatskillmountains'),

    def test_bazeries_transpose(self):
        cipher = goldbug.cipher.Bazeries(123)
        self.assertEqual(''.join(cipher._Bazeries__transpose("abcdefghij")),
                         'acbfedgihj')
        cipher = goldbug.cipher.Bazeries(321)
        self.assertEqual(''.join(cipher._Bazeries__transpose("abcdefghij")),
                         'cbaedfihgj')

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Bazeries(512)
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_bazeries_misc(self):
        self.assertEqual(repr(goldbug.cipher.Bazeries(14)), 'Bazeries(14)')
        self.assertEqual(
            repr(goldbug.cipher.Bazeries(12, 'abcdefghijklmnoprstuvwxyz')),
            "Bazeries(12, alphabet='abcdefghijklmnoprstuvwxyz')"
        )

class BifidTest(unittest.TestCase):
    def test_bifid_encrypt(self):
        cipher = goldbug.cipher.Bifid('bgwkzqpndsioaxefclumthyvr')
        self.assertEqual(cipher.encrypt('fleeatonce'), 'uaeolwrins')

        poly = goldbug.util.Polybius('bgwkzqpndsioaxefclumthyvr')
        self.assertEqual(goldbug.cipher.Bifid(poly).encrypt('anything'),
                         cipher.encrypt('anything'))

        cipher = goldbug.cipher.Bifid('phqgmeaylnofdxkrcvszwbuti', 5)
        self.assertEqual(cipher.encrypt('defendtheeastwallofthecastle'),
                         'ffyhmkhycpliashadtrlhcchlblr')

    def test_bifid_decrypt(self):
        cipher = goldbug.cipher.Bifid('bgwkzqpndsioaxefclumthyvr')
        self.assertEqual(cipher.decrypt('uaeolwrins'), 'fleeatonce')

        poly = goldbug.util.Polybius('bgwkzqpndsioaxefclumthyvr')
        self.assertEqual(goldbug.cipher.Bifid(poly).decrypt('anything'),
                         cipher.decrypt('anything'))

        cipher = goldbug.cipher.Bifid('phqgmeaylnofdxkrcvszwbuti', 5)
        self.assertEqual(cipher.decrypt('ffyhmkhycpliashadtrlhcchlblr'),
                         'defendtheeastwallofthecastle')

    def test_bifid_bad(self):
        cipher = goldbug.cipher.Bifid('bgwkzqpndsioaxefclumthyvr')
        self.assertRaises(KeyError, cipher.encrypt, '!!!')
        self.assertRaises(KeyError, cipher.decrypt, '!!!')

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Bifid(goldbug.util.Polybius(''), 3)
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_bifid_misc(self):
        self.assertEqual(repr(goldbug.cipher.Bifid('bgwkzqpndsioaxefclumthyvr')),
                         "Bifid('bgwkzqpndsioaxefclumthyvr')")

        poly = goldbug.util.Polybius('bgwkzqpndsioaxefclumthyvr')
        self.assertEqual(repr(goldbug.cipher.Bifid(poly)),
                         "Bifid('bgwkzqpndsioaxefclumthyvr')")

        cipher = goldbug.cipher.Bifid('bgwkzqpndsioaxefclumthyvr', 3)
        self.assertEqual(repr(cipher), "Bifid('bgwkzqpndsioaxefclumthyvr', 3)")

class FractionatedMorseTest(unittest.TestCase):
    def test_fractionatedmorse_encrypt(self):
        cipher = goldbug.cipher.FractionatedMorse('morsecode')
        self.assertEqual(cipher.encrypt('attack tonight'), 'cntvhgzwndahma')

    def test_fractionatedmorse_decrypt(self):
        cipher = goldbug.cipher.FractionatedMorse('morsecode')
        self.assertEqual(cipher.decrypt('cntvhgzwndahma'), 'attack tonight')

    def test_fractionatedmorse_bad(self):
        self.assertRaises(ValueError, goldbug.cipher.FractionatedMorse,
                          'bad.key')
        self.assertRaises(KeyError,
                          goldbug.cipher.FractionatedMorse('test').decrypt,
                          'bad.ciphertext')

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_fractionatedmorse_unicode(self):
        cipher = goldbug.cipher.FractionatedMorse('test')
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_fractionatedmorse_misc(self):
        self.assertEqual(repr(goldbug.cipher.FractionatedMorse('test')),
                         "FractionatedMorse('test')")

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
                          goldbug.util.Polybius('', 'abcd'), 2)

        cipher = goldbug.cipher.Trifid('abcdefgh', 3)
        self.assertRaises(KeyError, cipher.decrypt, 'ijklm')

    @unittest.skipIf(sys.version_info[0] > 2, 'No string in Python 3')
    def test_unicode(self):
        cipher = goldbug.cipher.Trifid('abcdefghijklmnopqrstuvwxyz.')
        self.assertEqual(type(cipher.encrypt('something')), type('something'))
        self.assertEqual(type(cipher.encrypt('something'.decode('utf8'))),
                         type('something'.decode('utf8')))

    def test_trifid_misc(self):
        self.assertEqual(repr(goldbug.cipher.Trifid('abcdefgh', 3)),
                         "Trifid('abcdefgh', 3)")
        self.assertEqual(repr(goldbug.cipher.Trifid('.', -1)),
                         "Trifid('.')")


if __name__ == '__main__':
    unittest.main()
