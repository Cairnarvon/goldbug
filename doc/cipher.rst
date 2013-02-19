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

.. class:: Atbash(alphabet="abcdefghijklmnopqrstuvwxyz")

   Arbash is a kerless substitution cipher, originally for the Hebrew alphabet.
   It consists of substituting the first letter of the alphabet for the last,
   the second for the penultimate, and so on; hence the name (אתבש). It is a
   reciprocal cipher, meaning two successive applications will yield the
   original plaintext.

   This implementation works on the 26-letter alphabet by default. It's
   possible to make it use other alphabets.

      >>> import goldbug
      >>> cipher = goldbug.cipher.Atbash("אבגדהוזחטיכלמנסעפצקרשת")
      >>> cipher.encrypt("לב קמי")
      'כש דימ'

   If you're using Python 2.x, remember to pass :class:`unicode` objects if
   your alphabet isn't ASCII.

   :param alphabet: the ordered alphabet to use.

.. class:: Caesar(key)

   The Caesar cipher, also known as the shift cipher or Caesar shift, is a
   monoalphabetic substitution cipher in which each letter of the alphabet is
   replaced by a letter some fixed number of positions down the alphabet.
   This number is the key.

   It is named after Julius Caesar, who supposedly used it for his personal
   correspondence.

   :param key: an integer, ideally between 0 and 26.

.. class:: Keyword(key)

   The keyword cipher is a monoalphabetic substitution cipher using a keyword
   as the key. The alphabet is appended to the key, and duplicate letters are
   removed. The result is then aligned with the plaintext alphabet to obtain
   the substitution mapping.

   For example, with the key ``SECRET``:

   +----------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   |                | ↓ |                                                                                                   |
   +================+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+===+
   | **Plaintext**  | A | B | C | D | E | F | G | H | I | J | K | L | M | N | O | P | Q | R | S | T | U | V | W | X | Y | Z |
   +----------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   | **Ciphertext** | S | E | C | R | T | A | B | D | F | G | H | I | J | K | L | M | N | O | P | Q | U | V | W | X | Y | Z |
   +----------------+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

   :param key: a short string.

.. class:: Rot13()

   ROT13 is a special case of the :class:`Caesar` cipher. In effect, it is the
   Caesar cipher with the key set to 13. It is a reciprocal cipher, meaning two
   successive applications will yield the original text. It is keyless.

   It became particularly popular on Usenet, where it was often used to obscure
   spoilers and punchlines to jokes.
