import random
import math
import random
from math import gcd

def is_prime(n, k=5):
    if n <= 1:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n as d*2^r + 1
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_n_bit_prime(n, limit=None):
    while True:
        candidate = random.getrandbits(n)
        # Ensure the number has N bits and is odd
        candidate |= (1 << (n - 1)) | 1
        if limit is not None and candidate > limit:
            continue
        if is_prime(candidate):
            return candidate


def is_prime_2(n):
    """Check if a number is prime"""
    for i in range(2,n):
        if (n % i) == 0:
            return False
    return True

def euler_func(p, q):
    """Count the positive integers (up to p*q) that are relatively prime to p*q"""
    return (p - 1) * (q - 1)

def extended_euclidean_algorithm(a, b):
    """Extended Euclidean algorithm for finding gcd, x, y"""
    if a == 0 :
        return b, 0, 1
    gcd,x1,y1 = extended_euclidean_algorithm(b % a, a)
    x = y1 - (b // a) * x1
    y = x1 
    return gcd, x, y

def modular_inverse(num, mod):
    return extended_euclidean_algorithm(num, mod)[1] % mod

def generate_keys(bit_length):
    """Generate public and private keys"""
    # Generation of p and q
    half_bit_length = bit_length // 2
    while True:
        p = random.randint(2**(half_bit_length-1), 2**half_bit_length-1)
        if is_prime_2(p):
            break
    while True:
        q = random.randint(2**(half_bit_length-1), 2**half_bit_length-1)
        if is_prime_2(q) and p != q:
            break
    # Calculation of the module
    n = p * q
    # Public key creation
    phi = euler_func(p, q)
    while True:
        e = random.randint(3, phi - 1)
        if extended_euclidean_algorithm(e, phi)[0] == 1:
            break
    pub_key = (e, n)
    # Private key creation
    d = modular_inverse(e, phi)
    priv_key = (d, n)
    return pub_key, priv_key 
