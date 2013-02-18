from distutils.core import setup

setup(
    name='goldbug',
    version='0.0.1',
    description='Classical cryptography toolkit',
    longdescription='''\
This package implements a number of classical (that is, pre-computing era)
ciphers, as well as some tools to help break them.''',
    author='Koen Crolla',
    author_email='cairnarvon@gmail.com',
    url='https://github.com/Cairnarvon/goldbug',
    packages=['goldbug', 'goldbug.freq'],
    classifiers=['Intended Audience :: Education',
                 'License :: OSI Approved :: GNU General Public License v2 or later (GPLv2+)',
                 'Programming Language :: Python :: 2',
                 'Programming Language :: Python :: 3',
                 'Topic :: Security :: Cryptography']
)
