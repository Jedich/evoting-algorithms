import random
import string
import elgamal

import rsa
import primes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa as rsarsa

class Voter:
    def __init__(self, name):
        self.name = name
        self.public_key, self.private_key = self.generate_keypair()
        self.sign_pb, self.sign_pk = elgamal.elgamal_keypair()
        self.saved_ballots = []
        self.saved_keys = []
        self.names = ["a", "b", "c", "d"]
        self.test_string = ""

    def generate_keypair(self):
        a = primes.generate_keys(9)
        return a
    
    def generate_text(self, size=6):
       return ''.join(random.choice(string.digits + string.ascii_uppercase) for _ in range(size))
    
    def encrypt_with_all_keys(self, voter_public_keys, candidate):
        vo = voter_public_keys.copy()
        vo.reverse()
        a = self.names.copy()
        a.reverse()
        key = self.generate_text()
        self.saved_keys.append(key)
        result_ballot = rsa.to_byte(candidate) + rsa.to_byte(f":{key}")
        self.test_string = f"V,R{len(self.saved_keys)}"

        for i, voter_pb in enumerate(vo):
            result_ballot = rsa.rsa_encrypt(voter_pb, result_ballot, False)
            self.saved_ballots.append(result_ballot)
            self.test_string = f"E{a[i]}({self.test_string})"
        

       #vo.reverse()
        for i, voter_pb in enumerate(vo):
            key = self.generate_text()
            self.saved_keys.append(key)
            ballot_with_text = result_ballot + rsa.to_byte(f":{key}")
            self.test_string = f"E{a[i]}(R{len(self.saved_keys)},{self.test_string})"
            result_ballot = rsa.rsa_encrypt(voter_pb, ballot_with_text, False)
            self.saved_ballots.append(result_ballot)

        print(self.test_string)
        self.key_counter = len(self.saved_keys)
        return result_ballot

    def decrypt_part(self, i, ballot_list, test_list = [], key_counter = 0):
        if test_list == []:
            test_list = [self.test_string, self.test_string, self.test_string, self.test_string]
        new_ballot_list = []
        found_ballot = False
        for j, ballot in enumerate(ballot_list):
            if ballot in self.saved_ballots:
                found_ballot = True
            decrypted = rsa.rsa_decrypt(self.private_key, ballot, False)
            for key in self.saved_keys:
                if decrypted[-len(key):] == rsa.to_byte(key):
                    # print(rsa.to_byte(key))
                    found_ballot = True
                    break

            del decrypted[len(decrypted) - 7:]
            for k in range(0, (6 - key_counter)):
                test_list[j] = test_list[j].replace(f"R{5-k},", '', 1)
            new_ballot_list.append(decrypted)

            if new_ballot_list[j] in self.saved_ballots:
               found_ballot = True

            test_list[j] = test_list[j].replace(f"E{self.name.lower()}(", '', 1)[:-1]
            # print(test_list[j])
        key_counter -= 1
        
        if not found_ballot:
            #print(f"Виборець {self.name}yt знайшов свій бюлетень.")
            raise Exception(f"Бюлетень виборця {self.name} не знайдено.")
        else:  
            print(f"Виборець {self.name} знайшов свій бюлетень.")
        return new_ballot_list, test_list, key_counter
    
    def verify_ballot_signature(self, msg, signature, sign_pb):
        if not elgamal.verify(msg, signature, sign_pb):
            raise Exception("Підпис невірний.")
    
    def sign_part(self, i, ballot_list, sign_list, sign_pb, test_list = [], key_counter = 0):
        new_ballot_list = []
        new_sign_list = []
        found_ballot = False
        for j, ballot in enumerate(ballot_list):
            if i > 0:
                self.verify_ballot_signature(ballot, sign_list[j], sign_pb)
                test_list[j] = test_list[j].replace(f"S{self.names[i-1]}(", '', 1)[:-1]

            if ballot in self.saved_ballots:
                found_ballot = True
            decrypted = rsa.rsa_decrypt(self.private_key, ballot, False)
            # print(''.join([chr(c) for c in decrypted]))

            new_ballot_list.append(decrypted)
            new_sign_list.append(elgamal.sign(new_ballot_list[j], self.sign_pb, self.sign_pk))

            if new_ballot_list[j] in self.saved_ballots:
               found_ballot = True

            test_list[j] = f"S{self.names[i]}(" + test_list[j].replace(f"E{self.name.lower()}(", '', 1)[:-1] + ")"
            # print(test_list[j])
        key_counter -= 1
        if i > 0:
            print("Усі підписи вірні.")
        
        if not found_ballot:
            #print(f"Виборець {self.name}yt знайшов свій бюлетень.")
            raise Exception(f"Бюлетень виборця {self.name} не знайдено.")
        else:  
            print(f"Виборець {self.name} знайшов свій бюлетень.")
        return new_ballot_list, new_sign_list, test_list, key_counter
    
    def finalize_votes(self, i, ballot_list, sign_list, sign_pb):
        new_ballot_list = []
        found_ballot = False
        for j, ballot in enumerate(ballot_list):
            self.verify_ballot_signature(ballot, sign_list[j], sign_pb)
            
            decrypted = ''.join([chr(c) for c in ballot]).split(":")

            if decrypted[1] in self.saved_keys:
                found_ballot = True


            new_ballot_list.append(decrypted[0])

            if new_ballot_list[j] in self.saved_ballots:
               found_ballot = True

        if not found_ballot:
            #print(f"Виборець {self.name}yt знайшов свій бюлетень.")
            raise Exception(f"Бюлетень виборця {self.name} не знайдено.")
        else:  
            print(f"Виборець {self.name} перевірив підписи та знайшов свій бюлетень.")
    
        print(new_ballot_list)
        return new_ballot_list

candidates = ["Candidate A", "Candidate B"]
voter1 = Voter("A")
voter2 = Voter("B")
voter3 = Voter("C")
voter4 = Voter("D")

voter_public_keys = [voter1.public_key, voter2.public_key, voter3.public_key, voter4.public_key]
voter_order = [voter1, voter2, voter3, voter4]

b1 = voter1.encrypt_with_all_keys(voter_public_keys, "Candidate A")
b2 = voter2.encrypt_with_all_keys(voter_public_keys, "Candidate B")
b3 = voter3.encrypt_with_all_keys(voter_public_keys, "Candidate A")
b4 = voter4.encrypt_with_all_keys(voter_public_keys, "Candidate A")

ballot_list = [b1, b2, b3, b4]
sign_list = []

test_list = []
key_counter = 5
print("Етап 1:")
for i, voter in enumerate(voter_order):
    ballot_list, test_list, key_counter = voter.decrypt_part(i, ballot_list, test_list, key_counter)
    print(test_list[0])

print("Етап 2:")
for i, voter in enumerate(voter_order):
    pb = voter_order[i-1].sign_pb if i > 0 else ''
    ballot_list, sign_list, test_list, key_counter = voter.sign_part(i, ballot_list, sign_list, pb, test_list, key_counter)
    print(test_list[0])

print("Заключний етап:")
vote_list = []
for i, voter in enumerate(voter_order):
    pb = voter_order[3].sign_pb
    vote_list = voter.finalize_votes(i, ballot_list, sign_list, pb)

print("Результати голосування:")
for candidate in candidates:
    print(f"{candidate}: {vote_list.count(candidate)}")
