from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import binascii

def keyGen():
    return get_random_bytes(16)

def ivGen():
    return get_random_bytes(16)

def macKeyGen():
    k1=get_random_bytes(16)
    k2=get_random_bytes(16)
    return k1,k2 

def padding(block):
    global applied_padding
    l=len(block)/8
    l1=int((128-8*l)/(8))
    padding=l1.to_bytes((l1.bit_length() + 7) // 8, 'big')
    p= ' '.join(format(byte, '08b') for byte in padding)
    m1=str(block)+(p*l1)
    applied_padding=str(p*l1)
    print("applied_padding : ", applied_padding)
    return  m1

def incrementIv(iv):
    iv_list = bytearray(iv)
    carry = 1
    for i in range(len(iv_list)-1, -1, -1): 
        iv_list[i] += carry
        carry = iv_list[i] >> 8
        iv_list[i] &= 0xFF  
    return bytes(iv_list)


def Encrypt(key, block, iv):
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)
    byte_list = [block[i:i+8] for i in range(0, len(block), 8)]
    block1="".join(chr(int(byte, 2)) for byte in byte_list).encode()
    cipher1=cipher.encrypt(block1)
    return cipher1

def NMAC(message, k1,k2):
    h1=SHA256.new(k1+message.encode()).digest()
    return SHA256.new(k2+h1)

def Decrypt(key,block, iv):
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)
    plain1=cipher.encrypt(block)
    return plain1


def Verify_MAC(ciphertext, tag, k1,k2):
    computed_tag = NMAC(ciphertext, k1,k2).digest()
    return tag == computed_tag

def main():
    global applied_padding
    message=b'1111111111111111111111111111111111111111111111111111111111111111111111111'
    #message=b'ciaociaociaociaociaociaociaociao'
    #message=b'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
    #message=b""
    #message=b""
    print("original message: ", message)
    if(len(message)==0):
        return
    if(message==" ".encode()):
        return
    m = ' '.join(format(byte, '08b') for byte in message)
    m=m.replace(' ',"")
    message_block=[]
    block_size=128
    print("message len: ", len(m))

    #divide the message into blocks
    for i in range(0, len(m), block_size):
        message_block.append(m[i:i+block_size])
    print("message blocks: ", message_block)
    
    #check if padding needed
    if(len(message_block[-1])<128 and len(message_block[-1])%(8)==0):
        message_block[-1]=padding(message_block[-1])
    elif(len(message_block[-1])<128 and len(message_block[-1])%(8)!=0):
        print("The given input cannot be padded")
        return 0

    
    #----- ENCRYPTION -----
    enc_key=keyGen()
    enc_iv=ivGen()
    dec_iv=enc_iv
    cipher_block=[]

    #encrypt the blocks one by one
    for block in message_block:
        cipher=Encrypt(enc_key,block,enc_iv)
        enc_iv=incrementIv(enc_iv)
        cipher_block.append(cipher)
    encrypted_message=""
    if(len(cipher_block)==1):
       encrypted_message=cipher_block[0]
    for i in range (len(cipher_block)-1):
        #encrypted_message+=str(cipher_block[i])
        encrypted_message+=str(binascii.hexlify(cipher_block[i]).decode())
        #print(binascii.hexlify(cipher_block[i]).decode())
    print("encrypted message: ", encrypted_message)
    #m1 = ' '.join(format(byte, '08b') for byte in encrypted_message.encode())
    #m1=m1.replace(' ',"")
    #print("m1: ", m1)
    
    #generate tag
    (M_k1, M_k2)= macKeyGen()
    tag=NMAC(encrypted_message, M_k1, M_k2).digest()
    print("tag: ", tag)

    #----- TAG ALTERATION  -----

    tag=incrementIv(tag)

    #----- DECRYPTION -----
    #check the tag
    if(Verify_MAC(encrypted_message, tag , M_k1, M_k2)==0):
        print("The message has been alterated")
        return 0
    
    #if okay, then decrypt
    decrypted_block=[]
    for block in cipher_block:
        plaintext=Decrypt(enc_key,block,dec_iv)
        dec_iv=incrementIv(dec_iv)
        decrypted_block.append(plaintext)    
   
    #merge decrypted blocks
    decrypted_message=""
    if(len(decrypted_block)==1):
       decrypted_message=decrypted_block[0]
    for i in range (len(decrypted_block)):
        decrypted_message+=str(decrypted_block[i].decode()) 

    print("decrypted message: ", decrypted_message)
    return 1

if __name__ == "__main__":
    main()