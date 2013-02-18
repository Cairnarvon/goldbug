:mod:`goldbug.freq` --- n-gram frequency tables
===============================================

.. module:: goldbug.freq
   :synopsis: n-gram frequency tables

.. module:: goldbug.freq.english
   :synopsis: n-gram frequency tables for English

This package contains n-gram frequency tables for natural languages, which may
be of use in cryptanalysis.

Each language module contains at least two dictionaries: :data:`monogram` and
:data:`bigram`, with each key representing an n-gram and each value being its
frequency, as a number between 0 and 1.

The following languages are represented:

- :mod:`goldbug.freq.english` --- English. This module also contains :data:`trigram`.
