:mod:`goldbug.analysis` --- cryptanalysis
=========================================

.. module:: goldbug.analysis
   :synopsis: utilities for cryptanalysing classical ciphers

This module contains utilities for cryptanalysing the ciphers provided by
:mod:`goldbug.cipher`.

Text characterisation
---------------------

.. function:: chi2(text, freqs)

   Performs Pearson's chi-squared test on a potential plaintext with respect to
   a given frequency table. If the distributions are similar, the returned
   number will be lower.

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

       >>> goldbug.analysis.ic('abcdefghijklmnopqrstuvwxyz')
       0.0
       >>> goldbug.analysis.ic('how much wood would a woodchuck chuck if a woodchuck could chuck wood?')
       2.8345864661654137
       >>> goldbug.cipher.Caesar(14).encrypt('how much wood would a woodchuck chuck if a woodchuck could chuck wood?')
       'vck aiqv kccr kcizr o kccrqviqy qviqy wt o kccrqviqy qcizr qviqy kccr?'
       >>> goldbug.analysis.ic('vck aiqv kccr kcizr o kccrqviqy qviqy wt o kccrqviqy qcizr qviqy kccr?')
       2.8345864661654137

   If you want to calculate the di- or higher-graphic index of coincidence, just
   pass a list of appropriate n-grams as the second argument:

      >>> goldbug.analysis.ic('how much wood would a woodchuck etc.',
      ...                     goldbug.freq.english.bigram.keys())
      12.518518518518519
      >>> goldbug.analysis.ic('babbbcccbbcbaaacccaa',
      ...                     list(goldbug.util.textgen('abc', 3, 3)))
      0.3529411764705882

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
