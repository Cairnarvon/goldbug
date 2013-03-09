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

Substitution ciphers replace units of plaintext with units of ciphertext. They
may be **monoalphabetic**, in which case substitions are fixed and depend only
on the element itself and the key, or **polyalphabetic**, in which case other
factors, such as the position of the element in the text, will be at play as
well. If the elements on which the cipher acts are individual characters, it is
a **simple** substitution cipher; if it operates on groups of characters, it is
**polygraphic**.

.. class:: Affine(key, alphabet="abcdefghijklmnopqrstuvwxyz")

   The affine cipher is a monoalphabetic substitution cipher that maps each
   letter of the alphabet to another one through a simple mathematical function.
   Its key consists of two integers, *a* and *b*, the first of which must be
   prime relative to the length of the alphabet.

   To encrypt a letter, it is first transformed into a number (A becomes 0, B
   becomes 1, etc.), which is then multiplied by *a* and incremented by *b*,
   modulo the length of the alphabet. The resulting number is then turned back
   into a letter.

   The decryption step is the same in reverse: the number is decremented by *b*
   and multiplied by *a*'s multiplicative inverse modulo the length of the
   alphabet (see :func:`goldbug.util.mmi`).

   The reason *a* must be prime relative to the length of the alphabet is that
   the modular multiplicative inverse only exists if that is the case.

   :param key: a tuple of two integers, the first of which is prime relative to
               the length of the alphabet.
   :param alphabet: the alphabet.

.. class:: Atbash(alphabet="abcdefghijklmnopqrstuvwxyz")

   Arbash is a keyless substitution cipher, originally for the Hebrew alphabet.
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

.. class:: Autokey(key, alphabet='abcdefghijklmnopqrstuvwxyz')

   The autokey or autoclave cipher is a variation on the :class:`Vigenere`
   cipher, in which, rather than repeating the key indefinitely, the plaintext
   is appended to the key.

   Blaise de Vigenère's own version of this cipher used a single letter as the
   key; this implementation allows keywords of arbitrary length (greater than
   zero).

.. class:: Caesar(key)

   The Caesar cipher, also known as the shift cipher or Caesar shift, is a
   monoalphabetic substitution cipher in which each letter of the alphabet is
   replaced by a letter some fixed number of positions down the alphabet.
   This number is the key.

   It is named after Julius Caesar, who supposedly used it for his personal
   correspondence.

   :param key: an integer, ideally between 0 and 26.

.. class:: Chaocipher(left, right)

   The Chaocipher is a cipher designed by J. F. Byrne in 1918, and mentioned
   in his 1953 autobiography *Silent Years*. He believed it to be simple but
   unbreakable, and offered cash rewards to anyone who could break it. Nobody
   ever did, and the algorithm remained a mystery until May 2010, when the
   Byrne family donated all of Byrne's Chaocipher-related papers and artifacts
   to the National Cryptological Museum in Maryland.

   The cipher's key consists of two permuted alphabets, traditionally written
   around the edge of two disks. For every character being encrypted, the right
   disk is rotated until that character it at the top of the disk (the
   *zenith*), and the left disk is rotated by the same number of steps. The
   ciphertext character is character now at the left disk's zenith. After
   that, the disk alphabets are permuted as follows: the character to the
   right of the zenith on the left disk is removed, leaving a gap; this gap is
   closed by inserting the removed character at the bottom of the disk (the
   *nadir*) and moving the characters to its right up. The right disk is then
   rotated by one additional step, and the same thing happens with the
   character two positions to the right of its zenith.

   This process of dynamic substitution leads to what one genius described as
   "utter chaotification" of the plaintext. Decryption is the same process,
   except rotating the left disk and reading from the right; the permutation
   step is identical.

   :param left:
   :param right: Permuted alphabets.

.. class:: FourSquare(keys, alphabet=goldbug.util.Polybius(''), padding='x')

   The four-square cipher is a polygraphic substitution cipher by Félix
   Delastelle.

   It takes as its key two :class:`goldbug.util.Polybius` squares, and operates
   on plaintext characters within the domain of a third. These squares, all of
   which are the same size, are arranged as follows::

      alphabet    key1
      key2        alphabet

   By way of example, consider two keys ``Polybius('example')`` and
   ``Polybius('keyword')``, and a basic alphabet ``Polybius('')``. Arranged,
   they look like this::

       a b c d e  e x a m p
       f g h i k  l b c d f
       l m n o p  g h i k n
       q r s t u  o q r s t
       v w x y z  u v w y y

       k e y w o  a b c d e
       r d a b c  f g h i k
       f g h i l  l m n o p
       m n p q s  q r s t u
       t u v x z  v w x y z

   Encryption happens by taking plaintext characters in pairs, and locating the
   first one in the top left quadrant and the second in the bottom right one.
   The ciphertext characters are then the characters on the other two corners
   of the rectangle they form. In our example, the plaintext characters **ex**,
   for instance, would map to **az**.

   Because plaintext is taken in pairs, it is padded if its length isn't even.

   :param keys: a sequence of two :class:`goldbug.util.Polybius` squares.
   :param alphabet: a :class:`goldbug.util.Polybius` square.
   :param padding: a single character.

.. class:: Hill(key, alphabet='abcdefghijklmnopqrstuvwxyz')

   The Hill cipher is a polygraphic substitution cipher based on matrix
   operations, designed by Lester S. Hill in 1929.

   Each letter of our key and plaintext may be represented as a number in some
   fixed way; for instance, *a* becomes 0, *b* becomes 1, etc. For encryption,
   the key is written as a square matrix; for example, if our key is ``ddcf``:

   .. math::

      \left( \begin{array}{cc}
      3 & 3 \\
      2 & 5
      \end{array} \right)

   Our plaintext is broken up into chunks of a length equal to the key
   matrix's side, and written as column matrices. Each of these matrices is
   multiplied with the key matrix to yield the ciphertext. If our plaintext is
   ``help``:

   .. math::

      \left( \begin{array}{cc}
      3 & 3 \\
      2 & 5
      \end{array} \right)
      \left( \begin{array}{c}
      7 \\
      4
      \end{array} \right)
      =
      \left( \begin{array}{c}
      7 \\
      8
      \end{array} \right) \mod 26
      =
      h i

      \left( \begin{array}{cc}
      3 & 3 \\
      2 & 5
      \end{array} \right)
      \left( \begin{array}{c}
      11 \\
      15
      \end{array} \right)
      =
      \left( \begin{array}{c}
      0 \\
      19
      \end{array} \right) \mod 26
      =
      a t

   So our ciphertext is ``hiat``.

   Decryption is the same thing, only using the inverse of the key matrix
   modulo the length of the alphabet. This inverse doesn't exist for every
   matrix, so choose your key with care (:class:`Hill` will raise a
   :class:`ValueError` if you try to construct it with a key that can't be
   inverted).

   For our example, the inverse matrix is the following:

   .. math::

      \left( \begin{array}{cc}
      15 & 17 \\
      20 & 9
      \end{array} \right)

   Multiplying it by the ciphertext column matrices obtained earlier will
   yield the original plaintext column matrices.

   :param key: an instance of :class:`goldbug.util.Matrix` or a string to be
               used to create one, invertible modulo the length of the
               alphabet.
   :param alphabet: a string with no repeated characters.

.. class:: Homophonic(key)

   The homophonic substitution cipher is a simple substitution cipher that can
   map plaintext symbols to more than one ciphertext symbol, at random. This
   makes frequency analysis much harder.

   This class is just an alias for :class:`goldbug.cipher.Simple`; pass it a
   :class:`goldbug.util.RandomDict` to make it behave like a homophonic cipher.

      >>> d = goldbug.util.RandomDict({'a': ['y', '1', 'x'], 'b': ['?'], 'c': ['a', '&', 'e']})
      >>> goldbug.cipher.Homophonic(d).encrypt('aababcabbcc')
      'y1?1?a1??ea'
      >>> goldbug.analysis.ic('aababcabbcc')
      7.0909090909090908
      >>> goldbug.analysis.ic('y1?1?a1??ea')
      4.333333333333333

   Remember that :class:`Simple` preserves plaintext characters that aren't in
   its dictionary; if you want decryption to yield your original plaintext,
   be careful about that plaintext's characters *vis à vis* your mapping.

.. class:: KamaSutra(key)

   The Kama Sutra cipher is a early simple substitution cipher described in
   the 45th chapter of the Kama Sutra. It is also known as the Vātsyāyana
   cipher, after the Kama Sutra's purported author.

   Its key is a permutation of some alphabet. This permutation is written in
   two rows, and each plaintext character is replaced with the corresponding
   character in the other rows.

   For instance, if our key is ``bzjklpqvwmraunchysexdotgif``:

      +---+---+---+---+---+---+---+---+---+---+---+---+---+
      | b | z | j | k | l | p | q | v | w | m | r | a | u |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+
      | n | c | h | y | s | e | x | d | o | t | g | i | f |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+

   *b* gets turned into *n*, *c* gets turned into *z*, etc. Decryption is the
   exact same process as encryption.

   :param key: a permutation of the alphabet.

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

.. class:: Playfair(key, breaker='x', padding='z', omitted={'j': 'i'})

   The Playfair is a monoalphabetic digraph substitution cipher invented by
   Charles Wheatstone in 1854 and popularised by Lord Playfair.

   It uses a Polybius square with a key to map digraphs (that is, groups of two
   letters) to other digraphs in the following way:

   #. If the two letters are the same, insert an `x` (the :const:`breaker`
      parameter) between them and encrypt the new initial digraph.
   #. If the two letters form the opposite corners of a rectangle, they are
      replaced with the other two corners. Each character is replaced with the
      other corner on the same row.
   #. Otherwise, if the two letters are in the same row, they are replaced with
      the letters to the immediate right of them (wrapping around to the other
      side if needed).
   #. Otherwise, if the two letters are in the same column, they are replaced
      with the letters immediately below them (wrapping around to the other
      side if needed.)

   If necessary, the plaintext is padded with a `z` (the :const:`padding`
   parameter) to ensure it is of even length.

   Because a Polybius square only has room for 25 letters, one letter must be
   discarded; this is the :const:`omitted` parameter. By default, occurences of
   the letter `j` in the plaintext are mapped to `i`. Another common option is
   to discard the letter `q` entirely (`{'q': ''}`).

   :param key: a string.
   :param breaker: a single letter.
   :param padding: a single letter.
   :param omitted: a :class:`dict` mapping a letter to a letter or :const:`''`.

.. class:: Rot13()

   ROT13 is a special case of the :class:`Caesar` cipher. In effect, it is the
   Caesar cipher with the key set to 13. It is a reciprocal cipher, meaning two
   successive applications will yield the original text. It is keyless.

   It became particularly popular on Usenet, where it was often used to obscure
   spoilers and punchlines to jokes.

.. class:: Simple(key)

   The most straightforward substitution cipher: a simple, monoalphabetic cipher
   that takes a mapping from characters to other characters as its key.

   You can use this to recreate Poe's Gold-Bug cipher, after which
   :mod:`goldbug` was named:

      >>> cipher = goldbug.cipher.Simple({'a': '5', 'b': '2', 'c': '—', 'd': '†',
      ...                                 'e': '8', 'f': '1', 'g': '3', 'h': '4',
      ...                                 'i': '6', 'l': '0', 'm': '9', 'n': '*',
      ...                                 'o': '‡', 'p': '.', 'r': '(', 's': ')',
      ...                                 't': ';', 'u': '?', 'v': '¶', 'y': ':'})
      >>> print(cipher.decrypt('''\
      ... 53‡‡†305))6*;4826)4‡.)4‡);806*;48†8
      ... ¶60))85;1‡(;:‡*8†83(88)5*†;46(;88*96
      ... *?;8)*‡(;485);5*†2:*‡(;4956*2(5*—4)8
      ... ¶8*;4069285);)6†8)4‡‡;1(‡9;48081;8:8‡
      ... 1;48†85;4)485†528806*81(‡9;48;(88;4
      ... (‡?34;48)4‡;161;:188;‡?;'''))
      agoodglassinthebishopshostelinthede
      vilsseatfortyonedegreesandthirteenmi
      nutesnortheastandbynorthmainbranchse
      venthlimbeastsideshootfromthelefteyeo
      fthedeathsheadabeelinefromthetreeth
      roughtheshotfiftyfeetout

   If you're using Python 2.x, remember to pass :class:`unicode` objects if
   your alphabet isn't ASCII.

   :param key: a :class:`dict` mapping characters to characters. If you pass
               in a :class:`goldbug.cipher.RandomDict`, you get a
               :class:`Homophonic` cipher instead.

.. class:: TwoSquare(keys, horizontal=False)

   The two-square cipher, also called the double Playfair, is a compromise
   between :class:`Playfair` and :class:`FourSquare`, using two Polybius
   squares instead of one or four.

   The squares are arranged either horizontally or vertically, and character of
   the plaintext are taken in pairs and looked up as with the four-square
   cipher. If the characters are on the same row (in the horizontal arrangement)
   or column (in the vertical), they are preserved in the ciphertext.

   Two-square is a reciprocal cipher: encryption and decryption are the same
   process.

   :param keys: two instances of :class:`goldbug.util.Polybius`, sharing the
                same alphabet.
   :param horizontal: the squares are arranged vertically unless this is
                      :const:`True`.

.. class:: Vigenere(key, alphabet='abcdefghijklmnopqrstuvwxyz')

   The Vigenère cipher is a simple polyalphabetic substitution cipher first
   described by Giovan Battista Bellaso in 1553, and later misattributed to
   Blaise de Vigenère. Though it is easy to understand and implement, it often
   appears difficult to break, earning it its nickname as *le chiffre
   indéchiffrable*.

   Its key is a word or short phrase, which is repeated for the length of the
   plaintext. If our key is ``lemon`` and our plaintext is ``attackatdawn``,
   this looks like this:

      +---+---+---+---+---+---+---+---+---+---+---+---+
      | l | e | m | o | n | l | e | m | o | n | l | e |
      +---+---+---+---+---+---+---+---+---+---+---+---+
      | a | t | t | a | c | k | a | t | d | a | w | n |
      +---+---+---+---+---+---+---+---+---+---+---+---+

   The corresponding key and plaintext characters are then looked up in a
   :class:`goldbug.util.TabulaRecta`, yielding a ciphertext character.

   :param key: a string, all of whose characters must be present in the
               alphabet.
   :param alphabet: the alphabet used to construct the tabula recta.


Transposition ciphers
---------------------

Transposition ciphers produce ciphertext by permuting plaintext---that is,
transposing its elements. Elements on which the ciphers work may be individual
characters or groups of them.

.. class:: Column(key, pad='x')

   The columnar transposition cipher is a fairly straightforward transposition
   cipher, which permutes plaintext in two steps.

   First, the plaintext is padded until its length is a multiple of the key
   length and placed into columns below the key, as follows:

      +---+---+---+---+---+---+
      | C | I | P | H | E | R |
      +===+===+===+===+===+===+
      | t | h | i | s | i | s |
      +---+---+---+---+---+---+
      | a | n | e | x | a | m |
      +---+---+---+---+---+---+
      | p | l | e | x | x | x |
      +---+---+---+---+---+---+

   In this example, the plaintext is ``thisisanexample``, the key is ``CIPHER``,
   and the padding character is ``x``.

   In the second step, the columns are moved so that the key's characters are
   in alphabetical order:

      +---+---+---+---+---+---+
      | C | E | H | I | P | R |
      +===+===+===+===+===+===+
      | t | i | s | h | i | s |
      +---+---+---+---+---+---+
      | a | a | x | n | e | m |
      +---+---+---+---+---+---+
      | p | x | x | l | e | x |
      +---+---+---+---+---+---+

   Then the key row is removed, and the columns are catenated to form the
   ciphertext; in this case, ``tapiaxsxxhnlieesmx``.

   By itself, the columnar transposition cipher is fairly easy to break, but
   it continued to be used as part of more complex encryption schemes until
   some time into the 1950s.

   :param key: a short string with no repeated characters.
   :param pad: a single character used for padding.

.. class:: RailFence(key)

   The rail fence cipher, also called the zig-zag cipher, is a straightforward
   transposition cipher in which plaintext characters are written in a zig-zag
   across rails. The key is the number of rails used.

   If our plaintext is ``thisisanexample`` and our key is 4, this looks like
   this:

      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---------+
      | t |   |   |   |   |   | a |   |   |   |   |   | p |   |   | → tap   |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---------+
      |   | h |   |   |   | s |   | n |   |   |   | m |   | l |   | → hsnml |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---------+
      |   |   | i |   | i |   |   |   | e |   | a |   |   |   | e | → iieae |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---------+
      |   |   |   | s |   |   |   |   |   | x |   |   |   |   |   | → sx    |
      +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---------+

   The ciphertext is then read directly from the rails: ``taphsnmliieaesx``.

   If the message doesn't have more characters than there are rails, or there
   is only one rail, the ciphertext is identical to the plaintext, of course.

   :param key: a positive integer.

Other ciphers
-------------

These ciphers combine substitution with transposition, or have something
exotic going on that makes them difficult to classify.

.. class:: Bifid(key, period=0)

   The bifid cipher was invented around 1901 by Félix Delastelle, and was
   notable in that it combined fractionated substitution with transposition by
   way of a :class:`goldbug.util.Polybius` square.

   To demonstrate, let's use the following square as the key:

      +-------+-------+-------+-------+-------+-------+
      |       | **0** | **1** | **2** | **3** | **4** |
      +-------+-------+-------+-------+-------+-------+
      | **0** | b     | g     | w     | k     | z     |
      +-------+-------+-------+-------+-------+-------+
      | **1** | q     | p     | n     | d     | s     |
      +-------+-------+-------+-------+-------+-------+
      | **2** | i     | o     | a     | x     | e     |
      +-------+-------+-------+-------+-------+-------+
      | **3** | f     | c     | l     | u     | m     |
      +-------+-------+-------+-------+-------+-------+
      | **4** | t     | h     | y     | v     | r     |
      +-------+-------+-------+-------+-------+-------+

   To encrypt a message, the plaintext characters' coordinates are written
   vertically in a row, like so:

      +-------+---+---+---+---+---+---+---+---+---+---+
      |       | f | l | e | e | a | t | o | n | c | e |
      +=======+===+===+===+===+===+===+===+===+===+===+
      | **X** | 3 | 3 | 2 | 2 | 2 | 4 | 2 | 1 | 3 | 1 |
      +-------+---+---+---+---+---+---+---+---+---+---+
      | **Y** | 0 | 2 | 4 | 4 | 2 | 0 | 1 | 2 | 1 | 4 |
      +-------+---+---+---+---+---+---+---+---+---+---+

   (Our plaintext, obviously, is ``fleeatonce``.)

   The rows are the joined, and the numbers taken pairwise as the coordinates
   of our ciphertext characters:

     +--------+---+
     |        | ↓ |
     +========+===+
     | (3, 3) | u |
     +--------+---+
     | (2, 2) | a |
     +--------+---+
     | (2, 4) | e |
     +--------+---+
     | (2, 1) | o |
     +--------+---+
     | (3, 1) | l |
     +--------+---+
     | (0, 2) | w |
     +--------+---+
     | (4, 4) | r |
     +--------+---+
     | (2, 0) | i |
     +--------+---+
     | (1, 2) | n |
     +--------+---+
     | (1, 4) | s |
     +--------+---+

   Our ciphertext is then ``uaeolwrins``.

   Decryption is the whole thing in reverse.

   Longer messages are usually broken up into smaller chunks. The length of
   these chunks is called the **period** of the cipher.

   :param key: a :class:`goldbug.util.Polybius` square, or a string used to
               construct one.
   :param period: an integer; if non-positive, text will be encrypted and
                  decrypted whole.

.. class:: Trifid(key, period=0)

   The trifid cipher is another cipher by Félix Delastelle. It extends the
   :class:`Bifid` cipher into the third dimension; where the bifid cipher uses
   a Polybius *square* as the key, the trifid cipher uses a Polybius cube.

   Though the cube's side is canonically 3, allowing for a 27-character
   alphabet (usually the 26 letters and the period), this implementation allows
   for arbitrary sizes.

   Other than dealing with three coordinates instead of two, the trifid cipher
   works in essentially the same way as the bifid cipher.

   :param key: a :class:`goldbug.util.Polybius` cube (that is,
               **dimensions=3**), or a string of a length with an integral cube
               root (1, 8, 27, etc.) and no repeated characters.
   :param period: an integer; if non-positive, text will be encrypted and
                  decrypted whole.
