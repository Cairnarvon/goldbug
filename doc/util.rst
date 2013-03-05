:mod:`goldbug.util` --- utilities
=================================

.. module:: goldbug.util
   :synopsis: utilities for studying and breaking classical ciphers

Eventually this module will contain utilities for studying and breaking the
classical ciphers provided by :mod:`goldbug.cipher`.


Text characterisation
---------------------

.. function:: chi2(text, freqs)

   Performs Pearson's chi-squared test on a potential plaintext with respect to
   a given frequency table. If the distributions are similar, the returned
   number will be lower.

   A practical example, using chi-squared to help break the Caesar cipher
   through brute force:

      >>> import goldbug
      >>> from goldbug.freq.english import unigram
      >>> ciphertext = 'sjsfmhvwbuksgsscfgssawgpihorfsoakwhvwborfsoa'
      >>> candidates = {}
      >>> for i in range(26):
      ...     plaintext = goldbug.cipher.Caesar(i).decrypt(ciphertext)
      ...     candidates[plaintext] = goldbug.util.chi2(plaintext, unigram)
      ...
      >>> for candidate in sorted(candidates, key=candidates.__getitem__):
      ...    print('%8.2f %s' % (candidates[candidate], candidate))
      ...
         17.16 everythingweseeorseemisbutadreamwithinadream
         82.28 sjsfmhvwbuksgsscfgssawgpihorfsoakwhvwborfsoa
        156.45 ofobidrsxqgocooybcoowscledknbokwgsdrsxknbokw
        184.40 aranupdejcsaoaaknoaaieoxqpwznawisepdejwznawi
        225.78 gxgtavjkpiyguggqtuggokudwvcftgcoykvjkpcftgco
        226.57 pgpcjestyrhpdppzcdppxtdmfelocplxhtestylocplx
        254.46 lclyfaopundlzllvyzlltpzibahkylhtdpaopuhkylht
        264.26 ypylsnbchaqymyyilmyygcmvonuxlyugqcnbchuxlyug
        270.74 tktgniwxcvlthttdghttbxhqjipsgtpblxiwxcpsgtpb
        273.57 hyhubwklqjzhvhhruvhhplvexwdguhdpzlwklqdguhdp
        312.80 nenahcqrwpfnbnnxabnnvrbkdcjmanjvfrcqrwjmanjv
        323.04 fwfszuijohxftffpstffnjtcvubesfbnxjuijobesfbn
        333.77 ctcpwrfgleucqccmpqcckgqzsrybpcykugrfglybpcyk
        362.96 rirelguvatjrfrrbefrrzvfohgnqernzjvguvanqernz
        380.29 izivcxlmrkaiwiisvwiiqmwfyxehvieqamxlmrehvieq
        383.42 wnwjqlzafyowkwwgjkwweaktmlsvjwseoalzafsvjwse
        564.93 uluhojxydwmuiuuehiuucyirkjqthuqcmyjxydqthuqc
        601.25 bsbovqefkdtbpbblopbbjfpyrqxaobxjtfqefkxaobxj
        610.28 vmvipkyzexnvjvvfijvvdzjslkruivrdnzkyzeruivrd
        641.31 kbkxeznotmckykkuxykksoyhazgjxkgscoznotgjxkgs
        725.27 dudqxsghmfvdrddnqrddlhratszcqdzlvhsghmzcqdzl
        756.01 mdmzgbpqvoemammwzammuqajcbilzmiueqbpqvilzmiu
        991.86 jajwdymnslbjxjjtwxjjrnxgzyfiwjfrbnymnsfiwjfr
       1049.16 xoxkrmabgzpxlxxhklxxfblunmtwkxtfpbmabgtwkxtf
       1689.16 zqzmtocdibrznzzjmnzzhdnwpovymzvhrdocdivymzvh
       1877.85 qhqdkftuzsiqeqqadeqqyuengfmpdqmyiuftuzmpdqmy

   Note that this function can return :const:`inf` if the text contains a
   character or sequence the frequency table claims has a probability of 0
   for a text of the given length.

   :param text: a string.
   :param freqs: a frequency table, as from :mod:`goldbug.freq`.

.. function:: frequency_analysis(text, ngram=1)

   Generates an n-gram frequency table from a source text. Note that this does
   not filter out non-alphabetic characters or anything; if you want that, do
   it yourself first.

       >>> goldbug.util.frequency_analysis('mississipi', 2)
       {'ss': 0.25, 'ip': 0.125, 'is': 0.25, 'mi': 0.125, 'si': 0.25}

.. function:: ic(text, alphabet='abcdefghijklmnopqrstuvwxyz')

   Calculates the monographic index of coincidence for the given text with
   respect to the given alphabet.

   The IC gives a measure of how much the distribution of letters in a piece of
   text differs from a flat distribution, and is left unchanged by simple
   substitution ciphers (and all transposition ciphers).

       >>> goldbug.util.ic('abcdefghijklmnopqrstuvwxyz')
       0.0
       >>> goldbug.util.ic('how much wood would a woodchuck chuck if a woodchuck could chuck wood?')
       2.8345864661654137
       >>> goldbug.cipher.Caesar(14).encrypt('how much wood would a woodchuck chuck if a woodchuck could chuck wood?')
       'vck aiqv kccr kcizr o kccrqviqy qviqy wt o kccrqviqy qcizr qviqy kccr?'
       >>> goldbug.util.ic('vck aiqv kccr kcizr o kccrqviqy qviqy wt o kccrqviqy qcizr qviqy kccr?')
       2.8345864661654137

   It is also useful when cryptanalysing the Vigenère cipher.
   (Details to follow.)

   .. TODO

   Note that this implementation takes your text at face value. It doesn't
   touch case, and will happily chuck out capital letters (if you're using the
   default alphabet). Keep that in mind.

   Expected IC values for selected natural languages (courtesy of *Military
   Cryptanalytics, Part I, Volume 2*):

      +------------+------+
      | Language   | IC   |
      +============+======+
      | English    | 1.73 |
      +------------+------+
      | French     | 2.02 |
      +------------+------+
      | German     | 2.05 |
      +------------+------+
      | Italian    | 1.94 |
      +------------+------+
      | Portuguese | 1.94 |
      +------------+------+
      | Russian    | 1.76 |
      +------------+------+
      | Spanish    | 1.94 |
      +------------+------+


Other utilities
---------------

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

.. function:: egcd(a, b)

   This function implements the extended Euclidean algorithm. It returns a tuple
   *(g, x, y)* such that :math:`ax + by = g = gcd(a, b)`.

.. function:: mmi(a, m)

   This function computes the multiplicative inverse of *a* modulo *m*,
   raising a :class:`ValueError` if *a* is not prime relative to *m* (and
   the multiplicative inverse therefore doesn't exist).
