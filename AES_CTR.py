from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import binascii
applied_padding=""

def keyGen():
    return get_random_bytes(16)

def ivGen():
    return get_random_bytes(16)

def xor_bit_strings(bit_string1, bit_string2):
    if len(bit_string1) != len(bit_string2):
        raise ValueError("Bit strings must have equal length")

    result = [str(int(bit1) ^ int(bit2)) for bit1, bit2 in zip(bit_string1, bit_string2)]
    result=''.join(result)
    return result

def bits_to_hex(bit_string):
    if len(bit_string) % 8 != 0:
        raise ValueError("Bit string length must be a multiple of 8")

    byte_string = b""

    for i in range(0, len(bit_string), 8):
        byte_bits = bit_string[i:i+8]
        byte_value = int(byte_bits, 2)
        byte_string += bytes([byte_value])

    return byte_string

def Encrypt(key,block, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher1=cipher.encrypt(iv)
    #transform the encryption of iv into a bit string
    m = ' '.join(format(byte, '08b') for byte in cipher1)
    m=m.replace(' ',"")
    #xor between the encryption and the message block
    cipher2=xor_bit_strings(m, block)
    return cipher2 

def Decrypt(key,block, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    cipher1=cipher.encrypt(iv)
    #transform the encryption of iv into a bit string
    m = ' '.join(format(byte, '08b') for byte in cipher1)
    m=m.replace(' ',"")
    cipher2=xor_bit_strings(m, block)    
    return cipher2

def padding(block):
    global applied_padding
    l1=int((128-(len(block)))/(8))
    padding=l1.to_bytes((l1.bit_length() + 7) // 8, 'big')
    p= ' '.join(format(byte, '08b') for byte in padding)
    m1=str(block)+(p*l1)
    applied_padding=str(p*l1)
    return  m1

def incrementIv(iv):
    iv_list = bytearray(iv)
    carry = 1
    for i in range(len(iv_list)-1, -1, -1):  
        iv_list[i] += carry
        carry = iv_list[i] >> 8
        iv_list[i] &= 0xFF  
    return bytes(iv_list)

def main():

    #INPUT TESTS
    #message=b'1111111111111111111111111111111111111111111111111111111111111111111111111'
    #message=b'ciaociaociaociaociaociaociaociao'
    #message=b'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
    #message=b""
    #message=b" "
    #message=b'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'
    message=b"Hello, we are team 10"
    message_len=len(message)
    #message=b'ciao'
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
   
    #divide the message into blocks
    for i in range(0, len(m), block_size):
        message_block.append(m[i:i+block_size])

    #check if padding needed
    if(len(message_block[-1])<128 and len(message_block[-1])%(8)==0):
        message_block[-1]=padding(message_block[-1])
    
    elif(len(message_block[-1])<128 and len(message_block[-1])%(8)!=0):
        print("The given input cannot be padded")
        return 0
    #print("message block: ", message_block)
    
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
    #print("cipher block: ", cipher_block)
    
    #merge all the blocks into a single string
    encrypted_message=""
    if(len(cipher_block)==1):
       encrypted_message=cipher_block[0]
    for i in range (len(cipher_block)):
        encrypted_message=(encrypted_message)+(cipher_block[i])
    print("encrypted message: ", bits_to_hex(encrypted_message))
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
        decrypted_message+=str(decrypted_block[i])
    decrypted_message_str=''.join(chr(int(''.join(x), 2)) for x in zip(*[iter(decrypted_message)]*8))
    pos=bits_to_hex(decrypted_message)
    print("decrypted message: ", decrypted_message_str[0:message_len])
    return 1

if __name__ == "__main__":
    main()