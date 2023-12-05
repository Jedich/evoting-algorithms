from random import randint
import encrypt
import factor
import primes
import re
import rsa

class c:
    OKBLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[91m'
    BOLD = '\033[1m'
    BOLDGREEN = '\033[1m' + '\033[92m'
    END = '\033[0m'
    GRAY = '\033[30m'

class Candidate:
    def __init__(self, name, cea):
        self.name = name
        self.cea = cea
        self.id = cea.generate_id(6)
        cea.candidates[self.name] = self.id
        cea.candidate_names[self.id] = self.name

class CentralElectionAuthority:
    def __init__(self):
        self.eas = []
        self.candidates = {}
        self.candidate_names = {}
        self.voters = []
        self.votes = {}
        self.public_key, self.private_key = primes.generate_keys(24)
        self.eas = []

    def generate_id(self, n=5):
        range_start = 10**(n-1)-2
        range_end = (10**n)-1
        return randint(range_start, range_end)

    def get_candidate_id(self, candidate):
        if candidate not in self.candidates:
            raise Exception(f"Кандидата {candidate} не знайдено в списку ЦВК")
        return self.candidates[candidate]
    
    def has_voter(self, voter_id):
        return voter_id in self.voters

    def receive_vote(self, voter_id, encrypted_vote):
        if voter_id not in self.votes.keys():
            self.votes[voter_id] = []
        
        self.votes[voter_id].append(encrypted_vote)
    
    def calculate_results(self):
        result_dict = {}
        vote_dict = {}
        for candidate in self.candidates.values():
            result_dict[candidate] = 0

        for voter, vote_parts in self.votes.items():
            if len(vote_parts) != 2:
                raise Exception(f"Виборець {voter} має невірну кількість частин голосів")
            
            candidate_id = rsa.rsa_decrypt(self.private_key, vote_parts[0]*vote_parts[1])

            print(f"{c.GRAY}{vote_parts}, {self.candidates.values()}, {candidate_id}{c.END}")

            if candidate_id not in self.candidates.values():
                raise Exception(f"Кандидата {candidate_id} не знайдено в списку ЦВК")

            result_dict[candidate_id] += 1
            vote_dict[voter] = self.candidate_names[candidate_id]

        print(c.BOLD + '\033[96m' + "Голоси:" + c.END)
        for voter, candidate in vote_dict.items():
            print(f"{voter}: {candidate}")

        print(c.BOLD + '\033[96m' + "Результати голосування:" + c.END)
        for candidate_id, votes in result_dict.items():
            print(f"{self.candidate_names[candidate_id]}: {votes}")


class Voter:
    def __init__(self, name, cea):
        self.name = name
        self.cea = cea
        self.id = cea.generate_id(4)
        cea.voters.append(self.id)
        self.sign_pb, self.sign_pk = encrypt.generate_signature_key()

    def vote(self, candidate):
        try:
            candidate_id = self.cea.get_candidate_id(candidate)

            right, left = factor.find_coefficients(candidate_id)
            print(f"{c.GRAY}Частини: {right}, {left}{c.END}")

            messages = []
            messages.append(right)
            messages.append(left)

            encrypted_messages = []
            signatures = []
            for message in messages:
                msg = rsa.rsa_encrypt(self.cea.public_key, message)
                final_msg = f"{self.id}:{msg}"
                encrypted_messages.append(final_msg)
                signatures.append(encrypt.sign_message(final_msg, self.sign_pk))

            for i, ea in enumerate(self.cea.eas):
                ea.receive_vote(encrypted_messages[i], signatures[i], self.sign_pb)
        except Exception as e:
            print(c.WARNING + "Помилка:" + c.END, e)


class ElectionAuthority:
    def __init__(self, name, cea):
        self.name = name
        self.voted = []
        self.cea = cea
    
    def receive_vote(self, encrypted_vote, signature, signature_key):
        if not encrypt.verify_signature(encrypted_vote, signature, signature_key):
            raise Exception("Підпис не вірний")

        match = re.match(r'([^:]+):([^;]+)', encrypted_vote)

        if not match:
            raise Exception(f"{self.name}. Невірний формат повідомлення")

        voter_id, enc_message = match.group(1, 2)
        voter_id = int(voter_id)
        enc_message = int(enc_message)

        if not cea.has_voter(voter_id):
            raise Exception(f"{self.name}. Виборця {voter_id} не знайдено в списку виборців")

        if voter_id in self.voted:
            raise Exception(f"{self.name}. Виборець {voter_id} вже проголосував")
        
        self.voted.append(voter_id)
        cea.receive_vote(voter_id, enc_message)
        
        print(c.BOLDGREEN + f"{self.name}. " + c.END + c.GREEN + f"Голос від {voter_id} прийнято" + c.END)


candidates = ["Кандидат A", "Кандидат B"]

cea = CentralElectionAuthority()

ea = ElectionAuthority("ВК 1", cea)
ea2 = ElectionAuthority("ВК 2", cea)

cea.eas = [ea, ea2]

candidateA = Candidate("Кандидат A", cea)
candidateB = Candidate("Кандидат B", cea)

voter1 = Voter("Виборець 1", cea)
voter2 = Voter("Виборець 2", cea)
voter3 = Voter("Виборець 3", cea)
voter4 = Voter("Виборець 4", cea)

voter1.vote("Кандидат A")

voter2.vote("Кандидат B") 

voter3.vote("Кандидат A")
voter3.vote("Кандидат A") # Виборець, що голосує двічі

voter4.vote("Кандидат C") # Виборець, що голосує за неіснуючого кандидата
voter4.vote("Кандидат B")

cea.calculate_results()
