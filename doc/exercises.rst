Exercises
=========

Because you have too much free time. All of these problems are soluble using
:mod:`goldbug`, and shouldn't require more than intermediate programming
experience.


Problems
--------

The Gold-Bug
^^^^^^^^^^^^

You give a hobo some spare change, and he hands you a piece of paper on which
the following text is written::

   fbftxunrfutflrefmgeflofaqgkfngcuelbftflhuyfm
   gelggefgtlzsxaqgeuxravngtcltfanfaqgefpuoofxg
   staphfzxunavtxarulhhuqfgefcrlnnagpfmanflklck
   ugevnguhgeftfuxlrelnofungeffduxgunoatmftaqge
   unoxlnmgefutnvzpftxltfunrtflxunofbftccfltulz
   naglxarulhuxgnatlnlnltreuxgpvgumapfhufbfgelg
   gefeapaaqgeuxravngtcuxnagofggunolxwvltfmflh

You suspect that this is plain English encrypted with a simple substitution
cipher.

1. How can you confirm or refute your suspicion?
2. If you are right, how would you go about decrypting the note? You don't need
   a fully automatic solution; it's fine if you work out parts of it by hand.

Omnis Divisa in Partes Tres
^^^^^^^^^^^^^^^^^^^^^^^^^^^

How would you write a function that automatically breaks Caesar ciphers? You
may assume you know the language the plaintext is written in.


Solutions
---------

The Gold-Bug
^^^^^^^^^^^^

1. You could calculate the **index of coincidence** of the text using
   :func:`goldbug.analysis.ic` and compare it to expected IC value for English
   text. The IC is not affected by simple substitution ciphers. Our ciphertext's
   IC is 1.81, which compares favourably with the expected value of 1.73.

2. Frequency analysis (using :func:`goldbug.analysis.frequency_analysis`) is
   the first step. You can combine the resulting table with the frequency table
   for English language unigrams from :mod:`goldbug.freq.english` to create a
   likely mapping, either by hand or automatically:

      >>> freqs = goldbug.analysis.frequency_analysis(ciphertext)
      >>> sorted_cipherchars = sorted(freqs, key=freqs.get, reverse=True)
      >>> sorted_unigrams = sorted(goldbug.freq.english.unigram, key=goldbug.freq.english.unigram.get, reverse=True)
      >>> d = dict(zip(sorted_unigrams, sorted_cipherchars))
      >>> cipher = goldbug.cipher.Simple(d)
      >>> cipher.decrypt(ciphertext)
      'eweshaileaseolremtreodenptbeituaroweseocaxemtrottretsoyvhnptrahlngitsuosenienptrefaddehtvsnfceyhaingshnlaoccapetreuloiintfemnieoboubatrgitactreseaholroideaitreekahtaidnsmesnptraidhoimtreasigyfeshoseailseohaidewesuueosaoyintohnlaocahtinsoioioslrahtfgtamnfecaewetrottrernfnnptrahlngitsuahintdettaidohjgosemeoc'

   It's clear not every character is mapped correctly, but it's a good starting
   point. From here, you can apply a heuristic search algorithm using
   :func:`goldbug.analysis.chi2` with longer N-grams, swapping two characters in
   the substitution alphabet until the statistic for your tentative plaintext
   won't go any lower. The decrypted message is this::

      eversinceireachedtheageoftwentyihaverealized
      thatthetrampsofthiscountryareoneofthebiggest
      problemsinoursociallifetheycannotbedoneawayw
      ithuntilthereisachangeintheexistingorderofth
      ingsandtheirnumbersareincreasingeveryyeariam
      notasocialistnorananarchistbutidobelievethat
      thehoboofthiscountryisnotgettingasquaredeal

Omnis Divisa in Partes Tres
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The Caesar cipher only has 26 possible keys, so brute-forcing is very feasible.
The problem then is how you tell, without human intervention, whether any given
key is correct. This is easy with Pearson's chi-squared test
(:func:`goldbug.analysis.chi2`) and frequency tables for our plaintext
language: text in our target language will have a dramatically lower
chi-squared statistic than encrypted text.

Your function, then, could look something like this:

.. code-block:: python

   def break_caesar(ciphertext, lang=goldbug.freq.english):
      lowest_chi2 = float('inf')
      for key in range(26):
         plaintext = goldbug.cipher.Caesar(key).decrypt(ciphertext)
         chi2_stat = goldbug.analysis.chi2(plaintext, lang.unigram)
         if chi2_stat < lowest_chi2:
            lowest_chi2 = chi2_stat
            probable_plaintext = plaintext
      return probable_plaintext
