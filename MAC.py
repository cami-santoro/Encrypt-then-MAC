
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
    message="Hi we are team 10"
    print("Original message: ", message)
    (k1,k2)=keyGen()
    print("k1: ", k1)
    print("k2: ", k2)
    mac=Mac(message, k1, k2).digest()
    print("mac: ", mac)
    return 1

if __name__ == "__main__":
    main()