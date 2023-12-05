import primes
import rsa
from random import randint

class Ballot:
    def __init__(self, voter_id, index, candidate):
        self.voter_id = voter_id
        self.index = index
        self.candidate = candidate
    
    def __str__(self) -> str:
        return f"{self.voter_id}:{self.index}:{self.candidate}"

class Voter:
    def __init__(self, name, election_authority, generate_bad_id=False):
        self.name = name
        self.id = self.generate_id() if not generate_bad_id else self.generate_id(6)
        self.registration_message = f"id:{self.id},name:{self.name}"
        self.has_voted = False
        self.election_authority = election_authority
        self.public_key = election_authority.public_key
        self.r = primes.blind_factor(2048, self.public_key[1])

    def generate_id(self, n=5):
        range_start = 10**(n-1)
        range_end = (10**n)-1
        return str(randint(range_start, range_end))
    
    def generate_vote_set(self, candidate):
        candidates = self.election_authority.candidates.copy()
        if candidate not in self.election_authority.candidates:
            candidates.append(candidate)

        vote_set = []
        idx = 0
        for _ in range(10):
            vote_pack =  []
            for candidate in candidates:
                vote_pack.append(self.mask_ballot(Ballot(self.id, idx, candidate), self.r))
                idx += 1
            vote_set.append(vote_pack)

        return vote_set

    def mask_ballot(self, ballot, r):
        return rsa.rsa_blind(self.public_key, str(ballot), r, True)
    
    def unmask_ballot(self, ballot, r):
        s = [rsa.rsa_unblind(self.public_key, b, r) for b in ballot]
        return s
    
    def vote(self, candidate):
        try:
            vote_set = self.generate_vote_set(candidate)

            masked_signed_ballot = self.election_authority.validate_return_ballot(vote_set, self.r)

            signed_ballot = self.unmask_ballot(masked_signed_ballot, self.r)

            i = self.election_authority.get_candidate_index(candidate)
            self.election_authority.receive_vote(signed_ballot[i])
        except Exception as e:
            print(e)

        return

class ElectionAuthority:
    def __init__(self, candidates):
        self.candidates = candidates
        self.voted_users = []
        self.already_sent_ballots = []
        self.votes = []
        self.banned = []
        self.public_key, self.private_key = self.generate_keypair()

    def generate_keypair(self):
        return primes.generate_keys(12)
    
    def get_candidate_index(self, candidate):
        for i, c in enumerate(self.candidates):
            if c == candidate:
                return i

    def validate_return_ballot(self, vote_set, r):
        random_ballot_id = randint(0, len(vote_set) - 1)
        ballot_to_return = vote_set[random_ballot_id]
        del vote_set[random_ballot_id]
        voter_data = []

        for vote_pack in vote_set:
            for ballot in vote_pack:
                ballot = rsa.rsa_encrypt(self.private_key, ballot)
                voter_data, ok = self.verify_ballot(ballot, r)

                if voter_data[0] in self.banned:
                    raise Exception(f"Виборця {voter_data[0]} було виключено з голосування.")

                if not ok:
                    self.banned.append(voter_data[0])
                    raise Exception("Один з бюлетеней було невірно сформовано. Виборця виключено з голосування.")
                
                if voter_data[0] in self.already_sent_ballots:
                    raise Exception("Виборець вже надсилав набір бюлетеней.")
        
        self.already_sent_ballots.append(voter_data[0])
        return [rsa.rsa_encrypt(self.private_key, b) for b in ballot_to_return]

    def verify_ballot(self, ballot, r):
        s = rsa.rsa_unblind(self.public_key, ballot, r)
        m_st = rsa.rsa_decrypt(self.public_key, s, True)

        m_arr = m_st.split(":")
        uid, bid, msg = m_arr

        return m_arr, len(str(uid)) == 5 and msg in self.candidates

    def receive_vote(self, ballot):
        m_st = rsa.rsa_decrypt(self.public_key, ballot, True)
        uid, bid, msg = m_st.split(":")
        
        if uid in self.voted_users:
            raise Exception(f"Виборець {uid} вже голосував.")
        
        if uid in self.banned:
            raise Exception(f"Виборця {uid} було виключено з голосування.")

        if not len(str(uid)) == 5 and msg in self.candidates:
            self.banned.append(uid)
            raise Exception("Невірний бюлетень. Виборця виключено з голосування.")
        
        print(f"Голос враховано.")
        self.voted_users.append(uid)
        self.votes.append(f"{len(self.votes)}:{uid}:{msg}")
        return
        
    def print_results(self):
        vote_dict = {}
        for candidate in self.candidates:
            vote_dict[candidate] = 0

        for vote in self.votes:
            _, _, c = vote.split(":")
            vote_dict[c] += 1

        print("Результати голосування:")
        print(*vote_dict.items(), sep = "\n")

    def print_votes(self):
        print("Голоси:")
        print(*self.votes, sep = "\n")

# Створення кандидатів
candidates = ["Кандидат A", "Кандидат B"]

ea = ElectionAuthority(candidates)

voter1 = Voter("Виборець 1", ea)
voter2 = Voter("Виборець 2", ea, generate_bad_id=True)
voter3 = Voter("Виборець 3", ea)
voter4 = Voter("Виборець 4", ea)
voter5 = Voter("Виборець 5", ea)

print("v1 ca")
voter1.vote("Кандидат A")
print("v1 ca")
voter1.vote("Кандидат A")
print("v2 cb")
voter2.vote("Кандидат B")
print("v2 cb")
voter2.vote("Кандидат B")
print("v3 cb")
voter3.vote("Кандидат B")
print("v4 cc")
voter4.vote("Кандидат C")
print("v4 ca")
voter4.vote("Кандидат A")
print("v5 ca")
voter5.vote("Кандидат A")

ea.print_votes()
ea.print_results()
