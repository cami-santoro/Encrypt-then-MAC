from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import binascii
applied_padding=""

def keyGen():
    return get_random_bytes(16)

def ivGen():
    return get_random_bytes(16)

def Encrypt(key,block, iv):
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)
    #print("block: ", block)
    byte_list = [block[i:i+8] for i in range(0, len(block), 8)]
    block1="".join(chr(int(byte, 2)) for byte in byte_list).encode()
    #print("block1: ", block1)
    cipher1=cipher.encrypt(block1)
    return cipher1

def Decrypt(key,block, iv):
    cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)
    plain1=cipher.encrypt(block)
    return plain1

def padding(block):
    global applied_padding
    l1=int((128-(len(block)))/(8))
    print("l: ", l1)
    padding=l1.to_bytes((l1.bit_length() + 7) // 8, 'big')
    p= ' '.join(format(byte, '08b') for byte in padding)
    m1=str(block)+(p*l1)
    applied_padding=str(p*l1)
    print("applied_padding: ", applied_padding)
    return  m1

def incrementIv(iv):
    # Convert the IV to a list of bytes
    iv_list = bytearray(iv)
    # Iterate through each byte and increment it
    carry = 1
    for i in range(len(iv_list)-1, -1, -1):  # Iterate backwards
        iv_list[i] += carry
        carry = iv_list[i] >> 8
        iv_list[i] &= 0xFF  # Keep only the lowest 8 bits
    return bytes(iv_list)

def main():

    #INPUT TESTS
    message=b'1111111111111111111111111111111111111111111111111111111111111111111111111'
    message=b'ciaociaociaociaociaociaociaociao'
    #message=b'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
    #message=b""
    #message=b" "
    message=b'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
    message=b"Hello we are team 10"
    print("original message: ", message)
    global applied_padding
    if(len(message)==0):
        return
    if(message==" ".encode()):
        return
    
    #transform the message in its bit representation
    m = ' '.join(format(byte, '08b') for byte in message)
    m=m.replace(' ',"")
    
    message_block=[]
    block_size=128
    print("message len: ", len(m))
   
    #divide the message into blocks
    for i in range(0, len(m), block_size):
        message_block.append(m[i:i+block_size])
    #print("message blocks: ", message_block)
    print("last block before padding: ", message_block[-1])
    print("last block lenght: ", len(message_block[-1]))
    
    #check if padding needed
    if(len(message_block[-1])<128 and len(message_block[-1])%(8)==0):
        message_block[-1]=padding(message_block[-1])
        print("last block after padding: ", message_block[-1])
        print("lenght last block after padding: ", len(message_block[-1]))
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
    
    #merge all the blocks into a single string
    encrypted_message=""
    if(len(cipher_block)==1):
       encrypted_message=cipher_block[0]
    for i in range (len(cipher_block)-1):
        #encrypted_message+=str(cipher_block[i])
        encrypted_message+=str(binascii.hexlify(cipher_block[i]).decode())
        #print(binascii.hexlify(cipher_block[i]).decode())
    #print("encrypted message: ", encrypted_message)
    
    #----- DECRYPTION -----
    decrypted_block=[]
    for block in cipher_block:
        plaintext=Decrypt(enc_key,block,dec_iv)
        dec_iv=incrementIv(dec_iv)
        decrypted_block.append(plaintext)    

    #merge decrypted blocks into a single string
    decrypted_message=""
    if(len(decrypted_block)==1):
       decrypted_message=decrypted_block[0]
    for i in range (len(decrypted_block)):
        decrypted_message+=str(decrypted_block[i].decode()) 

    #print("decrypted message: ", decrypted_message)
    return 1

if __name__ == "__main__":
    main()