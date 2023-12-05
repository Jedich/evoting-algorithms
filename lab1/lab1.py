import os
from random import randint
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

class Voter:
    def __init__(self, name, election_authority, can_vote=True):
        self.name = name
        self.id = self.generate_id()
        self.registration_message = f"id:{self.id},name:{self.name}"
        self.can_vote = can_vote
        self.has_voted = False
        self.e_signature = election_authority.generate_signature(self.registration_message)
        self.election_authority = election_authority

    def generate_id(self, n=5):
        range_start = 10**(n-1)
        range_end = (10**n)-1
        return str(randint(range_start, range_end))

    def vote(self, candidate):
        if not self.can_vote:
            print(f"Голос від {self.name} не прийнято: немає права на голосування.")
            return
        if self.has_voted:
            print(f"Голос від {self.name} не прийнято: виборець не може голосувати декілька разів.")
            return
        
        try:
            # Закодувати голос за допомогою коду гамування
            encrypted_vote, encryption_key = self.encrypt_vote(candidate)
            # Подати голос до виборчої адміністрації
            self.election_authority.receive_vote(self, encrypted_vote, encryption_key, self.e_signature)
        except Exception as e:
            return

        self.has_voted = True

    def encrypt_vote(self, candidate):
        # Перетворюємо символи у байти
        message_bytes = candidate.encode('utf-8')

        key = os.urandom(len(message_bytes))
        key_bytes = bytes(key)
        # Використовуємо XOR для шифрування
        encrypted_bytes = [m_byte ^ k_byte for m_byte, k_byte in zip(message_bytes, key_bytes)]
        return encrypted_bytes, key
    
    def verify_vote(self):
        if self.has_voted:
            print(f"{self.name}: Голос був зареєстрований.")
        else:
            print(f"{self.name}: Голос не зареєстрований.")

class ElectionAuthority:
    def __init__(self, candidates):
        self.candidates = candidates
        self.votes = []
        self.key = self.generate_key()

    def generate_key(self):
        # Для спрощення, згенеруємо випадкову пару ключів
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def get_public_key(self):
        return self.key.public_key()
    
    def generate_signature(self, message):
        # Скласти повідомлення
        # Хешувати текст
        hashed_message = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hashed_message.update(message.encode('utf-8'))
        digest = hashed_message.finalize()

        # Сформувати цифровий підпис за допомогою приватного ключа
        signature = self.get_public_key().encrypt(
            digest,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Відправити текст із цифровим підписом отримувачу
        return signature
    
    def verify_signature(self, received_message, signature):
        # Хешувати отриманий текст
        hashed_received_message = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hashed_received_message.update(received_message.encode('utf-8'))
        digest_received = hashed_received_message.finalize()

        # Отримати хеш з цифрового підпису
        try:
            digest_signature = self.key.decrypt(
                signature,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return digest_received == digest_signature
            # Якщо перевірка вдається, повернути True
            return True
        except Exception as e:
            # Якщо перевірка не вдається, повернути False
            return False

    def receive_vote(self, voter, encrypted_vote, key, signature):
        # Перевірити підпис за допомогою відкритого ключа
        if not self.verify_signature(voter.registration_message, signature):
            print(f"Голос від {voter.name} не прийнято: підпис не є валідним.")
            raise Exception()

        # Розшифрувати голос за допомогою приватного ключа
        decrypted_vote = self.decrypt_vote(encrypted_vote, key)

        if decrypted_vote not in self.candidates:
            print(f"Голос від {voter.name} не прийнято: не існує кандидата.")
            raise Exception()

        self.votes.append(decrypted_vote)
        print(f"Голос від {voter.name} прийнято.")

    def decrypt_vote(self, encrypted_bytes, key):
        key_bytes = bytes(key)
        # Використовуємо XOR для розшифрування
        decrypted_bytes = [e_byte ^ k_byte for e_byte, k_byte in zip(encrypted_bytes, key_bytes)]
        # Перетворюємо байти у рядок, вказуючи кодування UTF-8
        decrypted_message = bytes(decrypted_bytes).decode('utf-8', errors='replace')

        return decrypted_message
        
    def print_results(self):
        print("Результати голосування:")
        for candidate in self.candidates:
            print(f"{candidate}: {self.votes.count(candidate)}")

# Створення кандидатів
candidates = ["Кандидат A", "Кандидат B"]

ea = ElectionAuthority(candidates)

# Створення виборців, реєстрація їх у системі та генерація ЕЦП
voter1 = Voter("Виборець 1", ea)
voter2 = Voter("Виборець 2", ea, can_vote=False)  # Виборець без права голосу
voter3 = Voter("Виборець 3", ea)
voter4 = Voter("Виборець 4", ea)
voter5 = Voter("Виборець 5", ea)

ea.verify_signature(voter1.registration_message, voter1.e_signature)
# Проведення голосування
voter1.vote("Кандидат A")
voter1.verify_vote()

voter2.vote("Кандидат B")  # Виборець без права голосу

voter3.vote("Кандидат A")
voter3.vote("Кандидат A")  # Виборець, що голосує двічі

voter4.vote("Кандидат C")  # Виборець, що голосує за неіснуючого кандидата
voter4.verify_vote()
voter4.vote("Кандидат B")

voter5.e_signature = voter4.e_signature  # Виборець, що голосує за іншого виборця
voter5.vote("Кандидат B")
voter5.verify_vote()

ea.print_results()
