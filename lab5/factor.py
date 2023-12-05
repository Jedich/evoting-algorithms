import random

def prime_factorization(n):
    factors = []
    i = 2
    while i * i <= n:
        if n % i:
            i += 1
        else:
            n //= i
            factors.append(i)
    if n > 1:
        factors.append(n)
    return factors

def find_coefficients(target_product):
    factors = prime_factorization(target_product)
    
    if len(factors) < 2:
        return 1, target_product if random.randint(0, 1) == 0 else target_product, 1

    # Introduce randomness by shuffling the factors
    random.shuffle(factors)

    coefficient1 = factors[0]
    coefficient2 = target_product // coefficient1

    return coefficient1, coefficient2

# Example usage:
# target_product = 11210
# result = find_coefficients(target_product)
# print(result)