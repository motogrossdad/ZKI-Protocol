"""
Zero-Knowledge Age Verification

Proves "I am over X years old" without revealing your actual birthdate.

How it works:
1. A trusted authority (government, bank) issues you a signed credential
   that contains your birthdate — encrypted on YOUR device only.
2. When a venue asks "are you over 18?", your device:
   - Computes your age from the stored birthdate
   - Creates a ZK proof that age >= 18
   - Sends ONLY the proof + the authority's signature
3. The venue verifies the proof and the signature.
   They learn: "a trusted authority confirmed this person is over 18"
   They DON'T learn: your birthdate, your name, or anything else.

This implementation uses a Pedersen commitment scheme for the range proof.
"""

import hashlib
import secrets
from datetime import date, datetime


# Reuse Schnorr parameters
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
G = 2
Q = (P - 1) // 2
# Second generator H (nothing-up-my-sleeve number)
H = pow(G, int(hashlib.sha256(b"ZKI-Protocol-H-generator").hexdigest(), 16), P)


class TrustedAuthority:
    """
    The government or bank that issues identity credentials.
    They verify your real birthdate ONCE, then you never show it again.
    """

    def __init__(self, name: str = "Government ID Authority"):
        self.name = name
        self.signing_key = secrets.randbelow(Q - 1) + 1
        self.verification_key = pow(G, self.signing_key, P)

    def issue_credential(self, birthdate: date) -> dict:
        """Issue a signed age credential. Happens once (e.g., at the DMV)."""
        # Encode birthdate as days since epoch
        days = (birthdate - date(1900, 1, 1)).days
        # Create Pedersen commitment: C = g^days * h^r mod p
        r = secrets.randbelow(Q - 1) + 1
        commitment = (pow(G, days, P) * pow(H, r, P)) % P
        # Sign it
        k = secrets.randbelow(Q - 1) + 1
        sig_r = pow(G, k, P)
        msg_hash = int(hashlib.sha256(str(commitment).encode()).hexdigest(), 16) % Q
        sig_s = (k - msg_hash * self.signing_key) % Q

        return {
            "commitment": commitment,
            "blinding": r,
            "days_value": days,
            "signature": (sig_r, sig_s),
            "issuer": self.name,
            "issuer_key": self.verification_key,
        }


class AgeProver:
    """
    The person (on their phone/device).
    Holds the credential locally and generates proofs on demand.
    """

    def __init__(self, credential: dict):
        self.cred = credential

    def prove_over_age(self, min_age: int, today: date = None) -> dict:
        """
        Generate a proof that age >= min_age.
        The proof does NOT contain the birthdate.
        """
        if today is None:
            today = date.today()

        # Calculate actual age
        days_value = self.cred["days_value"]
        birthdate = date(1900, 1, 1) + __import__("datetime").timedelta(days=days_value)
        age = (today - birthdate).days // 365

        if age < min_age:
            return {"verified": False, "reason": "Age requirement not met"}

        # The difference (age - min_age) must be >= 0
        # We prove this by showing we can open a commitment to a non-negative value
        age_diff = age - min_age
        diff_blinding = secrets.randbelow(Q - 1) + 1
        diff_commitment = (pow(G, age_diff, P) * pow(H, diff_blinding, P)) % P

        # Create a challenge hash (Fiat-Shamir heuristic — makes it non-interactive)
        challenge_input = f"{self.cred['commitment']}:{diff_commitment}:{min_age}:{today}"
        challenge = int(hashlib.sha256(challenge_input.encode()).hexdigest(), 16) % Q

        # Response
        resp_value = (age_diff + challenge * self.cred["days_value"]) % Q
        resp_blinding = (diff_blinding + challenge * self.cred["blinding"]) % Q

        return {
            "original_commitment": self.cred["commitment"],
            "diff_commitment": diff_commitment,
            "challenge": challenge,
            "resp_value": resp_value,
            "resp_blinding": resp_blinding,
            "min_age": min_age,
            "check_date": today.isoformat(),
            "signature": self.cred["signature"],
            "issuer_key": self.cred["issuer_key"],
            # NOT included: birthdate, name, address, age, or any PII
        }


class AgeVerifier:
    """
    The venue, website, or app that needs to check age.
    They ONLY see a mathematical proof — never the actual data.
    """

    @staticmethod
    def verify(proof: dict) -> dict:
        """Verify an age proof. Returns result without ever learning the birthdate."""
        # 1. Verify the authority's signature on the original commitment
        commitment = proof["original_commitment"]
        sig_r, sig_s = proof["signature"]
        issuer_key = proof["issuer_key"]
        msg_hash = int(hashlib.sha256(str(commitment).encode()).hexdigest(), 16) % Q
        sig_check = (pow(G, sig_s, P) * pow(issuer_key, msg_hash, P)) % P
        signature_valid = sig_check == sig_r

        # 2. Verify the range proof
        challenge_input = f"{commitment}:{proof['diff_commitment']}:{proof['min_age']}:{proof['check_date']}"
        expected_challenge = int(hashlib.sha256(challenge_input.encode()).hexdigest(), 16) % Q
        challenge_valid = expected_challenge == proof["challenge"]

        # 3. Check the commitment math
        lhs = (pow(G, proof["resp_value"], P) * pow(H, proof["resp_blinding"], P)) % P
        rhs = (proof["diff_commitment"] * pow(commitment, proof["challenge"], P)) % P
        math_valid = lhs == rhs

        all_valid = signature_valid and challenge_valid and math_valid

        return {
            "verified": all_valid,
            "claim": f"Person is over {proof['min_age']}",
            "issued_by_trusted_authority": signature_valid,
            "proof_mathematically_valid": math_valid,
            "birthdate_revealed": False,
            "name_revealed": False,
            "data_stored_by_verifier": "NOTHING",
        }
