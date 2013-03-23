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

Blaise de Vigenère
^^^^^^^^^^^^^^^^^^

Compare the Vigenère cipher (:class:`goldbug.cipher.Vigenere`) to the autokey
cipher (:class:`goldbug.cipher.Autokey`). What weakness in the former does the
latter address?

The following ciphertext has been encrypted with the Vigenère cipher::

   soybzygxgljpciubeubwzkrlqjhzoalfzqozvlpsqorztdnfkm
   flqebkcodrgutgbnlfhznirxfhuztlpjfegbokbxutqpefytcs
   loubehiedtyxosdrggoytzuuotkgsdelkjinheboshzzbhzzcl
   ypcjzvppplzottfbnoubnromkwipquovubsltxoyodwflynswh
   gntkkzumygtgekfwozmziicylcchguznscvbhjzcznvjnogcht
   cjkbnhbnyazwlwutywdobhjtsludbgxzpvuitycfwiwgxcwlou

Knowing that the text is in English, answer the following questions:

1. How long is the key?
2. What is the plaintext?


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

Blaise de Vigenère
^^^^^^^^^^^^^^^^^^

1. Since the key repeats, plaintext characters at fixed offsets will be
   encrypted with the same key character. Using trigram (or any N-gram that
   isn't 1) statistics, we can try to figure out the key length and its first
   three characters by enumerating all possible strings of length 3 and sliding
   those strings along the ciphertext. Testing candidate key **xyz** and key
   lengths 3 through 6 looks like this:

      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **ciphertext** | s | o | y | b | z | y | g | x | g | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **candidate**  | x | y | z | x | y | z | x | y | z | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **decrypted**  | v | q | z | e | b | z | j | z | h | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **likelihood** | 0.0       | 1.7e-07   | 1e-08     | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+

      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **ciphertext** | s | o | y | b | z | y | g | x | g | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **candidate**  | x | y | z |   | x | y | z |   | x | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **decrypted**  | v | q | z |   | c | a | h |   | j | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **likelihood** | 0.0       |   | 7.89e-06  |   |   | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+

      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **ciphertext** | s | o | y | b | z | y | g | x | g | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **candidate**  | x | y | z |   |   | x | y | z |   | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **decrypted**  | v | q | z |   |   | b | i | y |   | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **likelihood** | 0.0       |   |   | 6.8e-07   |   | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+

      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **ciphertext** | s | o | y | b | z | y | g | x | g | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **candidate**  | x | y | z |   |   |   | x | y | z | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **decrypted**  | v | q | z |   |   |   | j | z | h | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+
      | **likelihood** | 0.0       |   |   |   | 1e-08     | ... |
      +----------------+---+---+---+---+---+---+---+---+---+-----+

   *Likelihood* is how common a given "plaintext" trigram is in the English
   language. The sum of all likelihoods divided by the number of trigrams
   (because longer keys will lead to fewer trigrams being examined) suggests
   which key prefix and length are most likely. In code, this looks like this:

   .. code-block:: python

      def guess_key(ciphertext, lang=goldbug.freq.english) -> (str, int):
          """
          Takes Vigenère ciphertext and returns the first three characters of the key
          and the key's length.
          """
          # Tabula recta used for decryption
          tabula = goldbug.util.TabulaRecta(reverse=True)

          # Tuple holding probability, key prefix, and key length
          best_guess = 0.0, '', 0

          # Enumerate all possible key prefixes
          for keypart in goldbug.util.textgen(min_length=3, max_length=3):
              # Check all fairly reasonable key lengths
              for keylen in range(3, 11):
                  # Extract the trigrams from our ciphertext
                  trigrams = [ciphertext[i:i + 3] for i in range(0, len(ciphertext) - 2, keylen)]

                  # Decrypt those trigrams
                  trigrams = [''.join(tabula[pair] for pair in zip(trigram, keypart))
                              for trigram in trigrams]

                  # Calculate how likely those decrypted trigrams are
                  prob = sum(lang.trigram.get(trigram, 0.0) for trigram in trigrams) / len(trigrams)

                  # Update our best guess
                  if prob > best_guess[0]:
                      best_guess = prob, keypart, keylen
          return best_guess[1:]

   Let's run this on the given ciphertext:

      >>> guess_key(ciphertext)
      ('gol', 6)

   So our key probably has a length of 6, and its first three characters are
   **gol**.

2. Now we can just brute-force our way to the complete key; :math:`26^4` is only
   456,976 candidate keys to check. If our key were much longer, we could search
   for it in parts using trigram statistics like in the previous step. As it is,
   let's just check everything because CPU cycles are cheap nowadays:

   .. code-block:: python

      def find_key(ciphertext, keyprefix, keylength, lang=goldbug.freq.english):
          candidate = float('inf'), '' # chi² statistic, key
          suflen = keylength - len(keyprefix)
          for keysuffix in goldbug.util.textgen(min_length=suflen, max_length=suflen):
              key = keyprefix + keysuffix
              cipher = goldbug.cipher.Vigenere(key)
              chi2_stat = goldbug.analysis.chi2(cipher.decrypt(ciphertext), lang.unigram)
              if chi2_stat < candidate[0]:
                  candidate = chi2_stat, key
          return candidate[1]

   The key turns out to be **goldbug**, and this is our plaintext::

      manyyearsagoicontractedanintimacywithamrwilliamleg
      randhewasofanancienthuguenotfamilyandhadoncebeenwe
      althybutaseriesofmisfortuneshadreducedhimtowanttoa
      voidthemortificationconsequentuponhisdisastershele
      ftneworleansthecityofhisforefathersandtookuphisres
      idenceatsullivansislandnearcharlestonsouthcarolina

   Which is, of course, the opening paragraph of *The Gold-Bug*.
