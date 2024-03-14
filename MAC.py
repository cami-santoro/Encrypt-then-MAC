"""
Keygen():
    1. Sample k1, k2 ← {0, 1}^λ.
    2. Output kMAC = (k1, k2).
MAC(m, kMAC = (k1, k2)):
    1. Compute h1 = H(k1|m).
    2. Output H(k2|h1).

Implement the NMAC scheme described above using SHA-256 as hash
function and key kMAC = (k1, k2), where both k1 and k2 have length
128 bits. You should implement at least two functions, one which
generates the MAC key and one which computes the MAC tag. In
comparison to part 1, you may use a SHA-256 implementation of the
library that supports inputs of arbitrary length for this part of the exercise. (2 points)

"""
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

def keyGen():
    k1=get_random_bytes(16)
    k2=get_random_bytes(16)
    return k1,k2 

def Mac(message, k1, k2):
    h1=SHA256.new(k1+message.encode()).digest()
    print("h1: ", h1)
    return SHA256.new(k2+h1)

def main():
    message="ciao bella"
    (k1,k2)=keyGen()
    mac=Mac(message, k1, k2).digest()
    print("mac: ", mac)
    return 1

if __name__ == "__main__":
    main()