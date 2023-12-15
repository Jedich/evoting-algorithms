import math
from random import randint
import sys
import binascii

"""
Algorithm of Miller-Rabin
Implementation based on the following wikipedia page : 
https://fr.wikipedia.org/wiki/Test_de_primalit%C3%A9_de_Miller-Rabin
"""

def generate_bits(length, x, n):
    out = ''
    x0 = pow(x, 2, n)
    out += str(x0 % 2)
    xn = x0
    for _ in range(length-1):
        xn = pow(xn, 2, n)
        out += str(xn % 2)
    return out, x0

def generate_decrypt_bits(length, p, q, x0):
    out = ''
    l = math.lcm(p-1, q-1)
    n = p*q
    for i in range(length):
        ipow = pow(2, i, l)
        xi = pow(x0, ipow, n)
        out += str(xi % 2)
    return out


class BBS_Generator:
    def __init__(self, max, n):
        self.max = max
        self.n = n
        self.numbers_gen = []

    def __is_good_prime(self, number):
        return number % 4 == 3 and miller_rabin(number)

    def __choose_prime_number(self):
        random = randint(3, self.max - 1)
        while not self.__is_good_prime(random):
            random = randint(3, self.max - 1)
        return random
    
    def generate_key(self):
        p = self.__choose_prime_number()
        q = self.__choose_prime_number()
        return p, q

    def print(self):
        i = 0
        for x in self.numbers_gen:
            print("number ", i, " random value = ", x)
            i += 1


def miller_rabin_witness(a, n):
    # n must be => than 3 and a > 1
    if n < 3 or a <= 1:
        return False

    # compute n-1 = 2**s * d with d odd
    d = n - 1
    s = 0
    while s > 1:
        q, r = divmod(d, 2)
        if r == 1:
            break
        s += 1
        d = q
    if pow(a, d, n) == 1:
        return False  # n isn't a miller rabin witness
    for i in range(s):
        if pow(a, pow(2, i) * d, n) == n - 1:
            return False  # n isn't a miller rabin witness
    return True  # n is definitely composite


def miller_rabin(n, k=100):
    if n % 2 == 0:
        return False
    for _ in range(k):
        a = randint(2, n - 1)
        if miller_rabin_witness(a, n):
            return False
    return True

def euler_totient_function(n):
    result = n  # Initialize result as n

    # Check for divisibility by prime numbers
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            while n % i == 0:
                n //= i
            result -= result // i

    # Check for remaining prime factor
    if n > 1:
        result -= result // n

    return result

def generate_coprime(n):
    phi_n = euler_totient_function(n)
    k = randint(1, phi_n)

    # Find the k-th coprime number
    coprime_candidate = 1
    for _ in range(k):
        coprime_candidate += 1
        while not math.gcd(n, coprime_candidate) == 1:
            coprime_candidate += 1

    return coprime_candidate

def xor_bit_strings(str1, str2):
    if len(str1) != len(str2):
        raise ValueError("Bit strings must be of equal length")

    result = ''.join(str(int(bit1) ^ int(bit2)) for bit1, bit2 in zip(str1, str2))

    return result

def ascii_to_binary(text):
    binary_string = ''.join(format(ord(char), '08b') for char in text)
    return binary_string


def binary_to_ascii(binary_string):
    ascii_text = ''.join(chr(int(binary_string[i:i+8], 2)) for i in range(0, len(binary_string), 8))
    return ascii_text

# max_prime_number_arg = 1000
# nb_bits_output = 32
# nb_numbers_to_generate = 10

# bbs = BBS_Generator(max_prime_number_arg, nb_bits_output)
# p, q = bbs.generate_key()
# n = p*q
# x = generate_coprime(n)
# text = "aboba"
# bittext = ascii_to_binary(text)
# print(bittext)
# # print(f"A coprime number for {n} is: {x}")
# result, x0 = generate_bits(len(bittext), x, n)
# # print(result)
# result2 = generate_decrypt_bits(len(bittext), p, q, x0)
# # print(result2)

# a = xor_bit_strings(bittext, result)
# print(a)
# b = xor_bit_strings(a, result2)
# print(b)

# ascii_text = binary_to_ascii(b)

# print(ascii_text)

# # Example
# text_to_convert = "Hello"
# binary_representation = ascii_to_binary(text_to_convert)
# print(f"ASCII to Binary: {binary_representation}")

# # Example
# binary_to_convert = "10010001100101110110011011001101111"
# ascii_representation = binary_to_ascii(binary_representation)
# print(f"Binary to ASCII: {ascii_representation}")