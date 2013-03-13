#!/usr/bin/env python

"""
Utilities for studying and breaking classical ciphers.
"""

import collections
import string

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

def chi2(text, freqs):
    """
    Performs Pearson's chi-squared test on a potential plaintext with respect
    to a given frequency table. Lower numbers are better.
    freqs should be a table from goldbug.freq.*; for instance, to perform the
    test with respect to English unigrams, use goldbug.freq.english.unigram.
    """
    acc = 0
    for c in freqs:
        e_i = freqs[c] * len(text) / len(c) # Expected incidence
        c_i = text.count(c)                 # Observed incidence
        if e_i == 0.0 and c_i == 0:
            continue
        elif e_i == 0.0:
            acc += float('inf')
        else:
            acc += (c_i - e_i)**2 / e_i
    return acc

def ic(text, alphabet=string.ascii_lowercase):
    """
    Calculates the index of coincidence for a given piece of text.
    By default it calculates the monographic A-Z IC; pass it a list of bigrams
    (as goldbug.freq.*.bigrams.keys()), trigrams, &c. for polygraphic IC.
    """
    # Ensure all n-grams are the same size.
    n = len(alphabet[0])
    if any(n != len(gram) for gram in alphabet):
        raise ValueError("N-grams aren't all the same size!")

    # Clean input to the extent possible.
    text = ''.join(c for c in text if c in ''.join(alphabet))

    # Split the text into n-grams.
    grams = [text[i:i + n] for i in range(len(text) - n + 1)
             if text[i:i + n] in alphabet]
    if len(grams) < 2:
        raise ValueError('Text is too short!')

    ic = 0
    for gram in alphabet:
        fi = grams.count(gram)
        ic += fi * (fi - 1)
    return ic / (len(grams) * (len(grams) - 1) / float(len(alphabet)))
