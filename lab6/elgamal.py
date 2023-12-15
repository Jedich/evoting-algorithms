def num_range():
    return 10000, 100000

import random 
from math import pow
 
def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)
 
# Generating large random numbers
def gen_key(q):
 
    key = random.randint(num_range()[0], q)
    while gcd(q, key) != 1:
        key = random.randint(num_range()[0], q)
 
    return key
 
# Modular exponentiation
def power(a, b, c):
    x = 1
    y = a
 
    while b > 0:
        if b % 2 != 0:
            x = (x * y) % c
        y = (y * y) % c
        b = int(b / 2)
 
    return x % c
 
def elgamal_receiver_keypair():
    p = random.randint(num_range()[0], num_range()[1])
    g = random.randint(2, p)
 
    x = gen_key(p) # Private key for receiver
    y = power(g, x, p)

    return (p, g, y), x

# Asymmetric encryption
def encrypt(msg, public_key):
    p, g, y = public_key
 
    a = []
 
    k = gen_key(p) # Private key for sender
    a_ch = power(y, k, p)
    b = power(g, k, p)
     
    for i in range(0, len(msg)):
        a.append(msg[i])

    for i in range(0, len(a)):
        a[i] = a_ch * ord(a[i])
 
    return a, b
 
def decrypt(encrypted_msg, public_key, private_key):
    a, b = encrypted_msg
    x = private_key
    p, g, y = public_key
 
    dr_msg = []
    h = power(b, x, p)
    for i in range(0, len(a)):
        dr_msg.append(chr(int(a[i]/h)))

    return ''.join(dr_msg)

# def main():
#     public_key, private_key = elgamal_receiver_keypair()
#     receiver_keypair = public_key, private_key
#     msg = 'encrypti onєєє'
#     print("Original Message :", msg)
 
#     encrypted_msg = encrypt(msg, public_key)
#     dr_msg = decrypt(encrypted_msg, receiver_keypair)
#     dmsg = ''.join(dr_msg)
#     print("Decrypted Message :", dmsg)
 
 
# if __name__ == '__main__':
#     main()