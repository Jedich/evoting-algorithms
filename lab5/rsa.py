import primes

def to_byte(arr):
    return [ord(t) for t in arr]

def rsa_encrypt(public_key, initial_text, is_ch = False):
    e, n = public_key
    m_arr = initial_text
    if is_ch:
        m_arr = to_byte(initial_text)
    s_sh = pow(initial_text, e, n)
    return s_sh

def rsa_decrypt(private_key, encrypted_text, is_ch = False):
    d, n = private_key
    if is_ch:
        decrypted_text = [chr(pow(c, d, n)) for c in encrypted_text]
        return ''.join(decrypted_text)
    else:
        m = pow(encrypted_text, d, n)
        return m

# keys = primes.generate_keys(12)
# print(keys)
# # keys = ((119, 1643), (839, 1643))
# public_key, private_key = keys
# initial_text = "Виборець 1"
# print("m:", initial_text)

# s_sh = rsa_encrypt(private_key, initial_text, True)
# print(f"s': {s_sh}")

# m_st = rsa_decrypt(public_key, s_sh, True)
# print(f"m_decrypted: {m_st}")
