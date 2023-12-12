from random import randint
import elgamal
import encrypt
import re

class c:
    OKBLUE = '\033[94m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    ERROR = '\033[91m'
    BOLD = '\033[1m'
    BOLDGREEN = '\033[1m' + '\033[92m'
    END = '\033[0m'

class Bureau:
    def __init__(self, debug=False):
        self.registration_ids = {}
        self.enc_public_key, self.enc_private_key = elgamal.elgamal_receiver_keypair()
        self.debug = debug

    def generate_registration_id(self, n=10):
        range_start = 10**(n-1)
        range_end = (10**n)-1
        return str(randint(range_start, range_end))
    
    def register_voter(self, encrypted_message, signature, signature_key):
        message = encrypt.decrypt_message(encrypted_message, self.enc_public_key, self.enc_private_key)

        if not encrypt.verify_signature(message, signature, signature_key):
            raise Exception("Підпис повідомлення не вірний")

        match = re.match(r'name:([^;]+);register', message)

        if not match:
            raise Exception("Невірний формат повідомлення")

        name = match.group(1)

        if name in self.registration_ids.values():
            raise Exception(f"Виборець {name} вже зареєстрований")

        id = self.generate_registration_id()

        self.registration_ids[id] = name

        print(f"Виборця {name} зареєстровано. {id if self.debug else ''}")

        return id
    
    def send_voter_list(self, ea):
        ea.assigned_voters = self.registration_ids


class Voter:
    def __init__(self, name, custom_id, election_authority):
        self.name = name
        self.personal_id = custom_id
        self.registration_id = None
        self.election_authority = election_authority

    def get_registration_id(self, bureau):
        try:
            message = f"name:{self.name};register"

            signature, signature_key = encrypt.sign_message(message)

            encrypted_message = encrypt.encrypt_message(message, bureau.enc_public_key)

            self.registration_id = bureau.register_voter(encrypted_message, signature, signature_key)
        except Exception as e:
            print(c.WARNING + "Помилка від БР:" + c.END, e)

    def generate_id(self, n=3):
        range_start = 10**(n-1)
        range_end = (10**n)-1
        return str(randint(range_start, range_end))

    def vote(self, candidate):
        try:
            message = f"{self.personal_id}:{self.registration_id}:{candidate}"

            signature, signature_key = encrypt.sign_message(message)

            encrypted_vote = encrypt.encrypt_message(message, self.election_authority.enc_public_key)

            self.election_authority.receive_vote(encrypted_vote, signature, signature_key)
        except Exception as e:
            print(c.ERROR + "Помилка від ВК:" + c.END, e)


class ElectionAuthority:
    def __init__(self, name, candidates, bureau):
        self.name = name
        self.candidates = candidates
        self.bureau = bureau
        self.assigned_voters = {}
        self.votes = []
        self.enc_public_key, self.enc_private_key = elgamal.elgamal_receiver_keypair()
    
    def receive_vote(self, encrypted_vote, signature, signature_key):

        message = encrypt.decrypt_message(encrypted_vote, self.enc_public_key, self.enc_private_key)

        if not encrypt.verify_signature(message, signature, signature_key):
            raise Exception("Підпис не вірний")

        match = re.match(r'([^:]+):([^;]+):([^:]+)', message)

        if not match:
            raise Exception("Невірний формат повідомлення")

        voter_id, reg_id, candidate = match.group(1, 2, 3)

        if reg_id not in self.assigned_voters:
            raise Exception(f"Виборець {voter_id} не зареєстрований у БР")

        if candidate not in self.candidates:
            raise Exception(f"{voter_id}. Кандидата '{candidate}' не існує")
        
        if self.assigned_voters[reg_id] == None:
            raise Exception(f"Виборець {voter_id} вже проголосував")
        
        self.assigned_voters[reg_id] = None
        self.votes.append({"id": voter_id, "candidate": candidate})

        print(c.BOLDGREEN + f"{self.name}. " + c.END + c.GREEN + f"Голос від {voter_id} за кандидата {candidate} прийнято" + c.END)

    def print_votes(self):
        print(c.BOLD + f"{self.name}. Голоси:" + c.END)
        for vote in self.votes:
            print(f"{vote['id']}: {vote['candidate']}")

    def print_results(self):
        vote_dict = {}

        for candidate in self.candidates:
            vote_dict[candidate] = 0

        for vote in self.votes:
            candidate = vote["candidate"]
            vote_dict[candidate] += 1

        print(c.BOLD + '\033[96m' + "Результати голосування:" + c.END)
        print(*vote_dict.items(), sep = "\n")

candidates = ["Кандидат A", "Кандидат B"]

bureau = Bureau()
# bureau = Bureau(debug=True)

ea = ElectionAuthority("ВК 1", candidates, bureau)

voter1 = Voter("Виборець 1", "Voter_1_543685", ea)
voter2 = Voter("Виборець 2", "Voter_2_81273", ea)
voter3 = Voter("Виборець 3", "V3_982734", ea)
voter4 = Voter("Виборець 4", "Voter_4_112", ea)
voter5 = Voter("Виборець 5", "Voter_55334345", ea)

voter1.get_registration_id(bureau)
voter2.get_registration_id(bureau)
voter2.get_registration_id(bureau)
voter3.get_registration_id(bureau)
voter4.get_registration_id(bureau)

bureau.send_voter_list(ea)

voter1.vote("Кандидат A")

voter2.vote("Кандидат B") 

voter3.vote("Кандидат A")
voter3.vote("Кандидат A") # Виборець, що голосує двічі

voter4.vote("Кандидат C") # Виборець, що голосує за неіснуючого кандидата
voter4.vote("Кандидат B")
voter5.vote("Кандидат B")


ea.print_votes()

ea.print_results()
