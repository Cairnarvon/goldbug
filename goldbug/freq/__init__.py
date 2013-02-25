#!/usr/bin/env python

"""
n-gram frequency tables

This package contains n-gram frequency tables for various languages. Each
language-specific module will contain at least two dictionaries named unigram
and bigram, with each key representing an n-gram and each value being its
frequency, as a number between 0 and 1.
"""

from . import english
