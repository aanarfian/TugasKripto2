import sys
import random
from math import gcd
import sympy

def checkprime(p, q):
    if not sympy.isprime(p):
        print("ERROR p is not prime")
        sys.exit()
    if not sympy.isprime(q):
        print("ERROR q is not prime")
        sys.exit()

def genkey(a,b):
    p = int(a)
    q = int(b)

    checkprime(p, q)

    f = (p-1)*(q-1)
    n = p*q

    while 1:
        # random angka e 1<e<f dimana e coprime dengan f
        e = random.randint(1, f)
        if gcd(e, f) == 1:   # Condition for coprime
            break

    for i in range(1, n-1):
        if ((i * e) % f) == 1:
            d = i         # d is private key.
            break

    print("Public Key is:", e, n)
    print("Private Key is:", d, n)
    return(e,d,n)

def encrypt(msg, e, n):
    cipher_enc = []

    for c in msg:
        cipher_enc.append(pow(ord(c), e, n))
    print("Encrypted message:", cipher_enc)
    return(cipher_enc)

def decrypt(cipher_enc, d, n):
    cipher_dec = []

    for c in cipher_enc:
        cipher_dec.append(chr(pow(c, d, n)))
    print("Decrypted message:", cipher_dec)

    return(cipher_dec)


#contoh prime number : 6679	6689 6691 6701 6703	6709 6719 6733 6737	6761 6763 6779 6781	6791 6793 6803 6823	6827 6829 6833
if __name__ == "__main__":
    a = input("Enter a large prime no P:")
    b = input("Enter another large prime no Q:")
    msg = input("Enter the message:")
    RSA(a,b,msg)

