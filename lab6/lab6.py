import random
import re
import sqlite3
import string
import bbs
import elgamal

class c:
    OKBLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[91m'
    BOLD = '\033[1m'
    BOLDGREEN = '\033[1m' + '\033[92m'
    END = '\033[0m'
    GRAY = '\033[30m'

con = sqlite3.connect('token_user_db.db')
max_prime_number_arg = 1000
nb_bits_output = 32
bbs_g = bbs.BBS_Generator(max_prime_number_arg, nb_bits_output)

class Bureau:
    def generate_voter_ids(self, voter_num):
        self.voter_ids = [self.generate_id() for _ in range(voter_num)]

    def generate_text(self, size=6):
        return ''.join(random.choice(string.digits + string.ascii_uppercase) for _ in range(size))
                
    def generate_id(self, n=5):
        range_start = 10**(n-1)-2
        range_end = (10**n)-1
        return random.randint(range_start, range_end)
    
    def store_tokens(self, tokens):
        cur = con.cursor()
        for token in tokens:
            cur.execute(f"INSERT INTO bureau VALUES (?, ?, NULL, NULL)", (token['id'], token['t']))
        con.commit()
        print("Токени збережено в базу даних")

    def receive_token(self, user_data):
        rows = con.execute('SELECT * FROM bureau WHERE user_id IS NULL AND name IS NULL')
        data = rows.fetchone()
        if data is None:
            raise Exception("Всі токени вже використані")

        cur = con.cursor()
        cur.execute(f"UPDATE bureau SET user_id = ?, name = ? WHERE voter_id = ?", 
                    (user_data['user_id'], user_data['name'], data[0]))
        con.commit()
        print(f"╔Виборця {user_data['name']} зареєстровано.")

        username = f"{user_data['user_id']}{user_data['name']}{self.generate_text(4)}"
        pwd = self.generate_text(8)
        token = data[1]
        
        cur = con.cursor()
        cur.execute(f"INSERT INTO voters VALUES (?, ?)", (username, pwd))
        con.commit()

        return username, pwd, token

class ElectionAuthority:
    def __init__(self, candidates):
        self.tokens = []
        self.encrypted_votes = []
        self.voted = []
        self.candidates = candidates
        self.public_key, self.private_key = elgamal.elgamal_receiver_keypair()

    def generate_keys(self, voter_ids):
        for voter_id in voter_ids:
            p, q = bbs_g.generate_key()
            cur = con.cursor()
            cur.execute("INSERT INTO cea VALUES (?, ?, ?)", (voter_id, p, q))
            self.tokens.append({'id': voter_id, 't': f"{voter_id}:{p*q}"})
        con.commit()
        print("Ключі збережено в базу даних")

    def receive_vote(self, encrypted_vote):
        self.encrypted_votes.append(encrypted_vote)

    def calculate_results(self):
        vote_dict = {}
        for candidate in self.candidates:
            vote_dict[candidate] = 0
        
        for vote in self.encrypted_votes:
            try:
                decrypted_vote = elgamal.decrypt(vote, self.public_key, self.private_key)
                match = re.match(r'([^:]+):([^;]+):([^;]+)', decrypted_vote)

                if not match:
                    raise Exception(f"Невірний формат токену")

                enc_ballot, x0, voter_id = match.group(1, 2, 3)
                x0 = int(x0)
                voter_id = int(voter_id)

                if voter_id in self.voted:
                    raise Exception(f"Виборець вже голосував")

                rows = con.execute('SELECT * FROM cea WHERE voter_id = ?', (voter_id,))
                data = rows.fetchone()
                if data is None:
                    raise Exception(f"Виборця {voter_id} не знайдено")
                p, q = data[1], data[2]
                decrypt_bits = bbs.generate_decrypt_bits(len(enc_ballot), p, q, x0)
                decrypted = bbs.xor_bit_strings(enc_ballot, decrypt_bits)
                candidate = bbs.binary_to_ascii(decrypted)

                if candidate not in self.candidates:
                    raise Exception(f"Кандидата {candidate} не знайдено в списку ЦВК")

                self.voted.append(voter_id)
                vote_dict[candidate] += 1
            except Exception as e:
                print(c.WARNING + "Помилка:" + c.END, e)
                continue

        print("Результати голосування:")
        print(*vote_dict.items(), sep = "\n")
            
class Voter:
    def __init__(self, user_id, name, bureau, ea):
        self.user_id = user_id
        self.name = name
        self.bureau = bureau
        self.ea = ea
        self.username = ""
        self.password = ""
        self.token = ""
        self.vs = VotingSystem()

    def get_token(self):
        try:
            self.username, self.password, self.token = self.bureau.receive_token({'user_id': self.user_id, 'name': self.name})
            print(f"╚Виборець {self.name} отримав токен.")
        except Exception as e:
            print(c.WARNING + "Помилка:" + c.END, e)

    def vote(self, candidate):
        try:
            self.vs.auth(self.username, self.password)
            print(f"╔Виборець {self.name} авторизований.")
        except Exception as e:
            print(c.WARNING + "Помилка:" + c.END, e)
        
        encrypted_vote = self.vs.encrypt_vote(self.token, candidate, self.ea.public_key)
        ea.receive_vote(encrypted_vote)
        print(f"╚Виборець {self.name} надіслав зашифрований бюлетень.")
        
class VotingSystem:
    def auth(self, login, pwd):
        cur = con.cursor()
        cur.execute(f"SELECT * FROM voters WHERE username = ? AND password = ?", (login, pwd))
        data = cur.fetchone()
        if data is None:
            raise Exception("Невірний логін або пароль")
        return True
    
    def encrypt_vote(self, token, candidate, bureau_pb):
        match = re.match(r'([^:]+):([^;]+)', token)

        if not match:
            raise Exception(f"Невірний формат токену")

        voter_id, n = match.group(1, 2)
        n = int(n)
        x = bbs.generate_coprime(n)
        bittext = bbs.ascii_to_binary(candidate)
        enc_code, x0 = bbs.generate_bits(len(bittext), x, n)
        result = bbs.xor_bit_strings(bittext, enc_code)

        encrypted = elgamal.encrypt(f"{result}:{x0}:{voter_id}", bureau_pb)
        return encrypted



cur = con.cursor()
cur.execute("DELETE FROM bureau")
cur.execute("DELETE FROM cea")
cur.execute("DELETE FROM voters")
con.commit()

bureau = Bureau()
bureau.generate_voter_ids(4)

candidates = ["Candidate A", "Candidate B"]
ea = ElectionAuthority(candidates)
ea.generate_keys(bureau.voter_ids)
bureau.store_tokens(ea.tokens)

v1 = Voter(1, "Василь", bureau, ea)
v2 = Voter(12, "Степан", bureau, ea)
v3 = Voter(15, "Тетяна", bureau, ea)
v4 = Voter(123432, "Михайло", bureau, ea)
v5 = Voter(12343222, "Михайло2", bureau, ea)

voters = [v1, v2, v3, v4]

for voter in voters:
    voter.get_token()

v5.get_token()

v1.vote("Candidate A")
v2.vote("Candidate A")
v3.vote("Candidate C")
v3.vote("Candidate B")
v4.vote("Candidate B")
v4.vote("Candidate B")

ea.calculate_results()
# step_1()

con.close()