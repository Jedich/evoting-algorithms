import hashlib
import random
import primes

bit_length = 16

def gcd(a, b):
    if a < b:
        return gcd(b, a)
    elif a % b == 0:
        return b
    else:
        return gcd(b, a % b)

def gen_k(start, p):
 
    key = random.randint(start, p-2)
    while gcd(p-1, key) != 1:
        key = random.randint(start, p-2)
 
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

def is_prime(num):
    if num < 2:
        return False
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0:
            return False
    return True

def get_first_n_bits(num, n):
    # Use a bitmask to extract the first N bits
    bitmask = (1 << n) - 1
    result = num & bitmask
    return result

def elgamal_keypair():
    p = primes.generate_n_bit_prime(bit_length, None)
    g = primes.generate_n_bit_prime(bit_length, p)
    x = random.randint(1, p-2)
    y = power(g, x, p)

    return (p, g, y), x

def sign(msg, public_key, private_key):
    p, g, y = public_key
    x = private_key
    k = gen_k(2, p)  # Random number for signing
    r = power(g, k, p)
    m = get_first_n_bits(int(hashlib.sha256((''.join([chr(c) for c in msg]).encode())).hexdigest(), 16), bit_length)
    pm = p-1
    s = ((m - x * r) * pow(k, -1, pm)) % pm
    return r, s

def verify(msg, signature, public_key):
    p, g, y = public_key
    r, s = signature

    m = get_first_n_bits(int(hashlib.sha256((''.join([chr(c) for c in msg]).encode())).hexdigest(), 16), bit_length)
    left_side = power(g, m, p)
    right_side = (power(y, r, p) * power(r, s, p)) % p

    return left_side == right_side 

# Example usage:
# public_key, private_key = elgamal_keypair()
# signer_keypair = public_key, private_key
# msg = 'Виборець 1'
# print("Original Message:", msg)

# signature = sign(msg, public_key, private_key)
# print("Signature:", signature)

# verification_result = verify(msg, signature, public_key)
# print("Verification Result:", verification_result)
