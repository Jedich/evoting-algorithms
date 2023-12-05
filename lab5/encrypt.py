from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.backends import default_backend

def verify_signature(received_message, signature, sender_public_key):
    try:
        sender_public_key.verify(
            signature,
            received_message.encode('utf-8'),
            algorithm=hashes.SHA256()
        )
        return True
    except:
        return False
    
def sign_message(message, private_key):
    hash_algorithm = hashes.SHA256()
    signature = private_key.sign(
        message.encode('utf-8'),
        algorithm=hash_algorithm
    )
    return signature

def generate_signature_key():
    private_key = dsa.generate_private_key(
        key_size=1024,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key, private_key
