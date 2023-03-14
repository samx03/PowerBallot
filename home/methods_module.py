import smtplib
from email.message import EmailMessage
from django.conf import settings
from django.utils import timezone

import random, string, datetime, time
from django.forms.models import model_to_dict

from .models import Voters, PoliticalParty, Vote, Block, VoteBackup, MiningInfo
from .merkle_tool import MerkleTools

from Crypto.Hash import SHA3_256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
import binascii
from cryptography.hazmat.primitives.asymmetric import ec, utils
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption, load_pem_private_key
# from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric.dsa import DSAParameterNumbers, DSAPrivateKey, DSAPublicKey, generate_private_key
from cryptography.hazmat.primitives.asymmetric import dsa
import hashlib

EMAIL_ADDRESS = settings.EMAIL_ADDRESS
EMAIL_PASSWORD = settings.EMAIL_PASSWORD

def send_email_otp(email_to):
    otp = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(8))
    msg = EmailMessage()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email_to
    msg['Subject'] = 'Don\'t reply, OTP for email verfication'
    content = 'Verify your email id to get the private key to cast your priceless vote. '+ otp +' is your OTP for email verfication.\nThank you.'
    msg.set_content(content)
    msg.add_alternative('''\
        <!DOCTYPE html>
        <html>
            <body>
                Verify your email id to get the private key to cast your priceless vote.
                <h2 style="display:inline;">'''+ otp +'''</h2> is your OTP for email verfication.<br>
                Thank you.
            </body>
        </html>
    ''', subtype='html')

    try:
        smtp = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)
        return [True, otp]
    except Exception as e:
        return [False, str(e)]

def send_email_private_key(email_to, private_key):
    msg = EmailMessage()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = email_to
    msg['Subject'] = 'Don\'t reply, PRIVATE KEY for vote casting.'
    content = 'Paste the Following Private as it is in order to cast your vote.\n\n\n'+ private_key + '\n\n\nNOTE: DON\'T REMOVE -----BEGIN PRIVATE KEY----- AND -----BEGIN PRIVATE KEY-----.\n\nThank you.'
    msg.set_content(content)

    try:
        smtp = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        smtp.send_message(msg)
        return [True]
    except Exception as e:
        return [False, str(e)]

def generate_keys():

    key = ECC.generate(curve='P-256')
    private_key = key.export_key(format='PEM')
    public_key = key.public_key().export_key(format='PEM')

    return private_key, public_key

# Generate keys
private_key, public_key = generate_keys()


def verify_vote(private_key, public_key, ballot):
    try:
        # print("Ballot:", ballot)
        # print("Private key: ",private_key)
        # print("Public key: ",public_key)
        
        # Assuming private_key contains the private key in PEM format
        # private_key_bytes = private_key.encode()
        # private_key_pem = b'-----BEGIN PRIVATE KEY-----\n' + private_key_bytes + b'\n-----END PRIVATE KEY-----\n'
        # private_key = load_pem_private_key(private_key_pem, password=None)
        # print("Private key: ",private_key)
        # public_key = ECC.import_key(public_key)
        # print("Public key: ",public_key)

        # print('Ballot before hashing:', ballot)
        # ballot_hash = SHA3_256.new(ballot.encode())
        # print('Ballot hash:', ballot_hash.hexdigest())
        
        # signer = DSS.new(private_key, 'fips-186-3')
        # print("Signer: ",signer)
        # signature = signer.sign(ballot_hash)
        # print(signature)
        # print('Ballot signature:', ballot_signature.hex())

        # # Verify the signature
        # verifier = DSS.new(public_key, 'fips-186-3')
        # verifier.verify(ballot_hash, signature)

        private_key_bytes = private_key.encode()
        private_key_pem = b'-----BEGIN PRIVATE KEY-----\n' + private_key_bytes + b'\n-----END PRIVATE KEY-----\n'
        private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

        # Convert EllipticCurvePrivateKey to an RSA private key object
        private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )  
        private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
        print("Private key: ",private_key)

        public_key_bytes = public_key.encode()
        # public_key_pem =  public_key_bytes
        # public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

        # print("Public key: ",public_key)

        public_key = serialization.load_pem_public_key(
            public_key_bytes,
            backend=default_backend()
        )

        public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        public_key = serialization.load_pem_public_key(
            public_key,
            backend=default_backend()
        )

        print("Public Key",public_key)


        print('Ballot before hashing:', ballot)

        digest = hashes.Hash(hashes.SHA3_256(), backend=default_backend())
        digest.update(ballot.encode())
        ballot_hash = digest.finalize()

        print('Ballot hash:', ballot_hash.hex())

        # signer = private_key.sign(hashes.SHA256())
        # print("Signer: ",signer)

        signature = private_key.sign(
            data=ballot_hash,
            signature_algorithm=ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        print('Signature:', signature.hex())
        
        return [True, 'Your vote verified and Ballot is signed successfully.', hashlib.sha3_256(ballot.encode()).hexdigest(), signature.hex()]
    except Exception as e:
        return [False, str(e), 'N/A', 'N/A']
        

def vote_count():
    parties_id = PoliticalParty.objects.values_list('party_id', flat = True)
    votes = Vote.objects.all()
    vote_result = {party: votes.filter(vote_party_id = party).count() for party in parties_id}
    # print(vote_result)
    return vote_result

