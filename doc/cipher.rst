:mod:`goldbug.cipher` --- classical ciphers
===========================================

.. module:: goldbug.cipher
   :synopsis: cipher implementations

This module implements various classical ciphers. They're used something like
this:

    >>> from goldbug.cipher import Caesar
    >>> cipher = Caesar(4)
    >>> cipher.encrypt('Gallia est omnis divisa in partes tres.')
    'Keppme iwx sqrmw hmzmwe mr tevxiw xviw.'
    >>> cipher.decrypt('Keppme iwx sqrmw hmzmwe mr tevxiw xviw.')
    'Gallia est omnis divisa in partes tres.'

All ciphers inherit from a base class:

.. class:: Cipher

   Most, but not all, ciphers will accept some sort of key in their constructor.

   .. method:: encrypt(text)

      A method to produce ciphertext from plaintext.

   .. method:: decrypt(text)

      A method to produce plaintext from ciphertext.

They're documented below only to the extent that they differ from this basic
pattern.


Substitution ciphers
--------------------

.. class:: Caesar(key)

   The Caesar cipher, also known as the shift cipher or Caesar shift, is a
   monoalphabetic substitution cipher in which each letter of the alphabet is
   replaced by a letter some fixed number of positions down the alphabet.
   This number is the key.

   It is named after Julius Caesar, who supposedly used it for his personal
   correspondence.

   :param key: an integer, ideally between 0 and 26.

   .. method:: encrypt(text, strip=True)

      Because the Caesar cipher only operates on alphabetic character,
      non-alphabetic characters show up in the ciphertext unmolested, which
      will make cryptanalysis even easier. If this is undesirable, set the
      :data:`strip` parameter to :const:`True`.

.. class:: Rot13()

   ROT13 is a special case of the :class:`Caesar` cipher. In effect, it is the
   Caesar cipher with the key set to 13. It is a reciprocal cipher, meaning two
   successive applications will yield the original text. It is keyless.

   It became particularly popular on Usenet, where it was often used to obscure
   spoilers and punchlines to jokes.

