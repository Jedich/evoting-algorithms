import primes

def to_byte(arr):
    return [ord(t) for t in arr]

def rsa_blind(public_key, plain_text, r, is_ch = False):
    e, n = public_key
    #r = 6
    m_arr = plain_text
    if is_ch:
        m_arr = to_byte(plain_text)
    m_sh = [m * pow(r, e, n) % n for m in m_arr]
    return m_sh

def rsa_encrypt(private_key, blind_text):
    d, n = private_key
    s_sh = [pow(m_sh, d, n) for m_sh in blind_text]
    return s_sh

def rsa_decrypt(public_key, blind_text, is_ch = False):
    e, n = public_key
    if is_ch:
        decrypted_text = [chr(pow(s, e, n)) for s in blind_text]
        return ''.join(decrypted_text)
    else:
        m = [pow(s, e, n) for s in blind_text]
        return m

def rsa_unblind(public_key, blind_text, r):
    _, n = public_key
    s = [(s_sh * pow(r, -1, n)) % n for s_sh in blind_text]
    return s

# keys = primes.generate_keys(12)
# # keys = ((119, 1643), (839, 1643))
# public_key, private_key = keys
# initial_text = "Виборець 1"
# print("m:", initial_text)

# ## -- ВИБОРЕЦЬ -- ##
# m_sh, r = rsa_blind(public_key, initial_text, True)
# print(f"Ключі - {keys}, r = {r}")
# print(f"m': {m_sh}")

# ## -- ЦВК -- ##
# s_sh = rsa_encrypt(private_key, m_sh)
# print(f"s': {s_sh}")

# ## -- ВИБОРЕЦЬ -- ##
# s = rsa_unblind(public_key, s_sh, r)
# print(f"s: {s}")
# m_st = rsa_decrypt(public_key, s, True)
# print(f"m_decrypted: {m_st}")
