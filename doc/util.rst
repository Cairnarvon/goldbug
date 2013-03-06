:mod:`goldbug.util` --- utilities
=================================

.. module:: goldbug.util
   :synopsis: miscellaneous utilities

This module provides things that aren't ciphers themselves, but are useful for
or actually used by our ciphers.


Classes
-------

.. class:: Matrix(matrix=None, size=None)

   A class representing a matrix, intended for use with
   :class:`goldbug.cipher.Hill`. It supports most operations you'd expect:
   addition (scalar and matrix), multiplication (scalar and matrix), modulo
   (scalar), raising to positive integral powers, and inversion modulo an
   integer (with the :func:`pow` builtin function). It doesn't support generic
   inversion, and provides no way for calculating the determinant.

      >>> m = goldbug.util.Matrix([[1, 2], [3, 4]])
      >>> m + m
      Matrix([[2, 4], [6, 8]])
      >>> m * m
      Matrix([[7, 10], [15, 22]])
      >>> m ** 3
      Matrix([[37, 54], [81, 118]])
      >>> m * m == m ** 2
      True
      >>> pow(m, -1, 7)
      Matrix([[5, 1], [5, 3]])
      >>> m[1, 0]
      3
      >>> m[1, 1] = 8
      >>> m
      Matrix([[1, 2], [3, 8]])
      >>> m % 3
      Matrix([[1, 2], [0, 2]])

   :param matrix: a sequence of rows; if omitted, *size* must be specified.
   :param size: an integer (for a square matrix) or a tuple of integers
                representing a null matrix's dimensions.

.. class:: Polybius(key, alphabet='abcdefghiklmnopqrstuvwxyz', dimensions=2)

   The traditional Polybius square maps an alphabet onto a checkboard, possibly
   with the help of a key. It isn't particularly useful on its own, but it's
   used by several classical ciphers.

   This implementation generalises that and can map an alphabet to a square
   (the default), a cube, or any hypercube. It provides a :class:`dict`-like
   mapping from characters to coordinate tuples and vice versa. It's used by
   such ciphers are :class:`goldbug.cipher.Bifid` (square) and
   :class:`goldbug.cipher.Trifid` (cube).

   For dimensions lower than 3, it converts to a string nicely:

      >>> from goldbug.util import Polybius
      >>> kana = 'いろはにほへとちりぬるをわかよたれそつねならむうゐのおくやまけふこえてあさきゆめみしゑひもせすん。'
      >>> uesugi = Polybius('', kana)
      >>> print(uesugi)
      い ろ は に ほ へ と
      ち り ぬ る を わ か
      よ た れ そ つ ね な
      ら む う ゐ の お く
      や ま け ふ こ え て
      あ さ き ゆ め み し
      ゑ ひ も せ す ん 。

   If you're using Python 2.x, remember to pass :class:`unicode` objects if
   your key and alphabet aren't ASCII.

   :param key: a string, each character of which must appear in the alphabet.
   :param alphabet: a string of a length with an integral square root.

.. class:: RandomDict(dictionary=None, **kwargs)

   This is a dictionary that can return one of several values for each given
   key, at random. It's constructed in the same way ordinary :class:`dict`
   objects are constructed, except that each key must be a sequence.

      >>> d = goldbug.util.RandomDict(a=[1, 2, 3], b=[4], c=[5, 6])
      >>> d['a']
      3
      >>> d['a']
      1
      >>> d['b']
      4

   If you pass an instance of :class:`RandomDict` as a key to
   :class:`goldbug.cipher.Simple`, it turns it from a simple substitution
   cipher into a homophonic substitution cipher
   (:class:`goldbug.cipher.Homophonic`), which is much less vulnerable to
   frequency analysis.

   Note that this class doesn't implement every method :class:`dict` has.
   Specifically, it implements the following:

   .. function:: __getitem__(key)

      As described above. This method uses :func:`random.choice` to select the
      value it returns, and will raise a :class:`KeyError` if the key is not
      present in the dictionary.

   .. function:: get(key, default=None)

      As :func:`__getitem__`, except that it returns *default* if *key* isn't
      present in the dictionary.

   .. function:: items

      This returns a list of *(key, value)* tuples. If a key can match to
      multiple values, it will appear in this list multiple times.

         >>> goldbug.util.RandomDict(a=[1, 2, 3], b=[4], c=[5, 6]).items()
         [('a', 1), ('a', 2), ('a', 3), ('c', 5), ('c', 6), ('b', 4)]

   .. function:: iteritems

      As :func:`items`, except an iterator.

.. class:: TabulaRecta(alphabet='abcdefghijklmnopqrstuvwxyz', reverse=False)

   Constructs a tabula recta look-up from a given alphabet. For the basic Latin
   alphabet, this looks like this:

   .. image:: _static/tabula.svg
      :alt: tabula recta
      :align: center
      :width: 50%

   It provides a straight-forward mapping, so ``tabula['o', 'k']`` returns
   ``'y'``.

   If the *reverse* parameter is :const:`True`, a reverse look-up is provided.
   Note that while ``tabula[a, b] == tabula[b, a]`` in the normal case, this
   isn't true in the reversed case.

   This is used by :class:`goldbug.cipher.Vigenere`.


Functions
---------

.. function:: egcd(a, b)

   This function implements the extended Euclidean algorithm. It returns a tuple
   *(g, x, y)* such that :math:`ax + by = g = gcd(a, b)`.

.. function:: mmi(a, m)

   This function computes the multiplicative inverse of *a* modulo *m*,
   raising a :class:`ValueError` if *a* is not prime relative to *m* (and
   the multiplicative inverse therefore doesn't exist).

.. function:: textgen(alphabet='abcdefghijklmnopqrstuvwxyz', min_length=0, max_length=None)

   A generator generating all strings it is possible to form with a given
   alphabet, of length *min_length* through length *max_length* (or forever if
   that's :const:`None`).

      >>> list(goldbug.util.textgen('abc', max_length=2))
      ['', 'a', 'b', 'c', 'aa', 'ab', 'ac', 'ba', 'bb', 'bc', 'ca', 'cb', 'cc']
