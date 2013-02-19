#!/usr/bin/env python 

"""
Utilities for studying and breaking classical ciphers.
"""

import collections

def frequency_analysis(text, ngram=1):
    """
    Generates an n-gram frequency table from a source text.
    """
    freqs, total = collections.defaultdict(int), 0
    for i in range(len(text) - ngram + 1):
        freqs[text[i:i + ngram]] += 1
        total += 1
    for gram in freqs:
        freqs[gram] /= float(total)
    return dict(freqs)
