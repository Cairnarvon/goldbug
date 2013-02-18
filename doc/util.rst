:mod:`goldbug.util` --- utilities
=================================

.. module:: goldbug.util
   :synopsis: utilities for studying and breaking classical ciphers

Eventually this module will contain utilities for studying and breaking the
classical ciphers provided by :mod:`goldbug.cipher`. Right now, though, it only
contains one function.

.. function:: frequency_analysis(text, ngram=1)

   Generates an n-gram frequency table from a source text. Note that this does
   not filter out non-alphabetic characters or anything; if you want that, do
   it yourself first.

       >>> goldbug.util.frequency_analysis('mississipi', 2)
       {'ss': 0.25, 'ip': 0.125, 'is': 0.25, 'mi': 0.125, 'si': 0.25}

