import random
import string
import elgamal

import rsa
import primes

class c:
    OKBLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[91m'
    BOLD = '\033[1m'
    BOLDGREEN = '\033[1m' + '\033[92m'
    END = '\033[0m'
    GRAY = '\033[30m'

class Voter:
    def __init__(self, name):
        self.name = name
        self.public_key, self.private_key = self.generate_keypair()
        self.sign_pb, self.sign_pk = elgamal.elgamal_keypair()
        self.saved_ballots = []
        self.saved_keys = []
        self.key_size = 6

    def generate_keypair(self):
        return primes.generate_keys(9)
    
    def generate_text(self, size=6):
       return ''.join(random.choice(string.digits + string.ascii_uppercase) for _ in range(size))
    
    def verify_ballot_signature(self, msg, signature, sign_pb):
        if not elgamal.verify(msg, signature, sign_pb):
            raise Exception("Підпис невірний.")
        
    def encrypt_with_all_keys(self, voter_public_keys, candidate, return_test_str = False):
        vo = voter_public_keys.copy()
        vo.reverse()
        test_str = ""
        key = self.generate_text(self.key_size)
        self.saved_keys.append(key)
        result_ballot = rsa.to_byte(candidate) + rsa.to_byte(f":{key}")
        test_str = f"V,R{len(self.saved_keys)}"

        for i, voter_pb in enumerate(vo):
            result_ballot = rsa.rsa_encrypt(voter_pb, result_ballot, False)
            self.saved_ballots.append(result_ballot)
            test_str = f"E{chr(98 + len(voter_pb)-i)}({test_str})"
        
        for i, voter_pb in enumerate(vo):
            key = self.generate_text(self.key_size)
            self.saved_keys.append(key)
            ballot_with_text = result_ballot + rsa.to_byte(f":{key}")
            test_str = f"E{chr(98 + len(voter_pb)-i)}(R{len(self.saved_keys)},{test_str})"
            result_ballot = rsa.rsa_encrypt(voter_pb, ballot_with_text, False)
            self.saved_ballots.append(result_ballot)

        self.key_counter = len(self.saved_keys)
        if return_test_str:
            return result_ballot, test_str
        else:
            return result_ballot

    def decrypt_part(self, i, ballot_list, test_str, cheater_id = None, fabricate_ballot_id = None):
        new_ballot_list = []
        found_ballot = False

        if cheater_id is not None and cheater_id == i:
            ballot_list[fabricate_ballot_id] = self.encrypt_with_all_keys(pbs, "Candidate C")

        for j, ballot in enumerate(ballot_list):
            decrypted = rsa.rsa_decrypt(self.private_key, ballot, False)

            del decrypted[len(decrypted) - (self.key_size + 1):]
            new_ballot_list.append(decrypted)

            if new_ballot_list[j] in self.saved_ballots:
               found_ballot = True
            if ballot in self.saved_ballots:
                found_ballot = True

        test_str = test_str.replace(f"E{self.name.lower()}(", '', 1)[:-1]
        for k in range(0, (len(self.saved_keys) - len(ballot_list) + i)):
            test_str = test_str.replace(f"R{5-k},", '', 1)
        
        if not found_ballot:
            #print(f"Виборець {self.name}yt знайшов свій бюлетень.")
            raise Exception(f"Бюлетень виборця {self.name} не знайдено на першому етапі.")
        else:  
            print(f"Виборець {self.name} знайшов свій бюлетень.")
        return new_ballot_list, test_str
    
    def sign_part(self, i, ballot_list, sign_list, sign_pb, test_str = ''):
        new_ballot_list = []
        new_sign_list = []
        found_ballot = False

        for j, ballot in enumerate(ballot_list):
            if i > 0:
                self.verify_ballot_signature(ballot, sign_list[j], sign_pb)
            decrypted = rsa.rsa_decrypt(self.private_key, ballot, False)

            new_ballot_list.append(decrypted)
            new_sign_list.append(elgamal.sign(new_ballot_list[j], self.sign_pb, self.sign_pk))

            if ballot in self.saved_ballots:
                found_ballot = True
            if new_ballot_list[j] in self.saved_ballots:
               found_ballot = True
        test_str = f"S{chr(i + 97)}(" + test_str.replace(f"E{self.name.lower()}(", '', 1)[:-1] + ")"
        if i > 0:
            print(f"{c.GREEN}Усі підписи вірні.{c.END}")
            test_str = test_str.replace(f"S{chr(i + 96)}(", '', 1)[:-1]

        if not found_ballot:
            #print(f"Виборець {self.name}yt знайшов свій бюлетень.")
            raise Exception(f"Бюлетень виборця {self.name} не знайдено на другому етапі.")
        else:  
            print(f"Виборець {self.name} знайшов свій бюлетень.")
        return new_ballot_list, new_sign_list, test_str
    
    def finalize_votes(self, i, ballot_list, sign_list, sign_pb):
        new_ballot_list = []
        found_ballot = False
        for j, ballot in enumerate(ballot_list):
            self.verify_ballot_signature(ballot, sign_list[j], sign_pb)
            
            decrypted = ''.join([chr(c) for c in ballot]).split(":")

            new_ballot_list.append(decrypted[0])

            if decrypted[1] in self.saved_keys:
                found_ballot = True

        if not found_ballot:
            #print(f"Виборець {self.name}yt знайшов свій бюлетень.")
            raise Exception(f"Бюлетень виборця {self.name} не знайдено.")
        else:  
            print(f"{c.GREEN}Виборець {self.name} перевірив підписи та знайшов свій бюлетень.{c.END}")
    
        print(new_ballot_list)
        return new_ballot_list

experiments = [
    {"cheater_id": None, "fabricate": None},
    {"cheater_id": 0, "fabricate": 2},
    {"cheater_id": 1, "fabricate": 0},
]

debug = True

for i, experiment in enumerate(experiments):
    candidates = ["Candidate A", "Candidate B"]
    voter1 = Voter("A")
    voter2 = Voter("B")
    voter3 = Voter("C")
    voter4 = Voter("D")

    voter_order = [voter1, voter2, voter3, voter4]

    print(f"{c.BOLD}{c.OKBLUE}Експеримент {i+1}. {c.END}", end='')
    if experiment["cheater_id"] is not None:
        print(f"{c.OKBLUE}Виборець {voter_order[experiment['cheater_id']].name} підробляє бюлетень виборця {voter_order[experiment['fabricate']].name}.{c.END}", end='')
    print()
    pbs = [voter.public_key for voter in voter_order]
    b1 = voter1.encrypt_with_all_keys(pbs, "Candidate A")
    b2 = voter2.encrypt_with_all_keys(pbs, "Candidate B")
    b3 = voter3.encrypt_with_all_keys(pbs, "Candidate A")
    b4, test_str = voter4.encrypt_with_all_keys(pbs, "Candidate A", True)
    if debug:
        print(c.GRAY + test_str + c.END)

    ballot_list = [b1, b2, b3, b4]

    try:
        print(f"{c.BOLD}Етап 1:{c.END}")
        for i, voter in enumerate(voter_order):
            ballot_list, test_str = voter.decrypt_part(i, ballot_list, test_str, experiment["cheater_id"], experiment["fabricate"])
            if debug:
                print(c.GRAY + test_str + c.END)

        print(f"{c.BOLD}Етап 2:{c.END}")
        sign_list = []
        for i, voter in enumerate(voter_order):
            pb = voter_order[i-1].sign_pb if i > 0 else ''
            ballot_list, sign_list, test_str = voter.sign_part(i, ballot_list, sign_list, pb, test_str)
            if debug:
                print(c.GRAY + test_str + c.END)

        print("Заключний етап:")
        vote_list = []
        for i, voter in enumerate(voter_order):
            pb = voter_order[3].sign_pb
            vote_list = voter.finalize_votes(i, ballot_list, sign_list, pb)

        print(f"{c.BOLD}Результати голосування:{c.END}")
        for candidate in candidates:
            print(f"{candidate}: {vote_list.count(candidate)}")
    except Exception as e:
        print(c.WARNING + "Помилка:" + c.END, e)
