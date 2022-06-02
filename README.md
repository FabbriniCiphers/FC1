# FC1

FC1 is a a symmetric key algorithm that offers an unprecedented grade of
confidentiality. Based on the uniqueness of the modular multiplicative inverse of
a positive integer a modulo n and on its computability in a polynomial time, this
non-deterministic cipher can easily and quickly handle keys of millions or
billions of bits that an attacker does not even know the length of. The
algorithm’s primary key is the modulo, while the ciphertext is given by the
concatenation of the modular inverse of blocks of plaintext whose length is
randomly chosen within a predetermined range.

FC1 full specification is available on IACR (International Association for
Cryptologic Research), paper title "FC1: A Powerful, Non-Deterministic, Symmetric
Key Cipher" https://www.iacr.org/news/item/18288 

The algorithm was also published at the Internet Engineering Task Force (IETF)
website: "FC1 Algorithm Ushers In The Era Of Post-Alien Cryptography"
https://datatracker.ietf.org/doc/draft-fabbrini-algorithm-post-alien-cryptography/

The Encryption and Decryption e was tested on a Windows OS. This is a beta version
that is still under development and you might encounter some bugs. I would welcome
general comments and feedback at fc1@fabbrini.org. 
Download latest Julia stable release at https://julialang.org/downloads. In ’bin’
folder create following .txt files: plaintext.txt, primarykey.txt,
secondarykey.txt, ciphertext.txt, decryptedplaintext.txt. Input a binary string in
plaintext.txt, a binary integer in primarykey.txt, a decimal integer in
secondarykey.txt.


PRIMARY KEY GENERATION

PKeyGenPrimeMod allows you to generate a primary key consisting of a prime number * 
in a given range. Download the "Primes.jl" package in .zip format and place it in 
Julia's "bin" folder: https://github.com/JuliaMath/Primes.jl.


* PKeyGenCompMod file will be available soon to generate primary keys consisting 
  of multiple factors.
