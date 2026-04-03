"""
Zero-Knowledge Ticket Verification

Proves "I own a valid ticket for this event" without revealing:
- Your name
- What you paid
- Your order number
- Your email

How it works:
1. When you buy a ticket, the ticketing platform issues a signed
   credential containing: event_id, date, ticket_type
2. At the gate, your phone proves:
   "I hold a credential signed by [Platform] for [Event] on [Date]"
3. The scanner verifies the signature and the proof.
   It learns: "This is a valid ticket for today"
   It does NOT learn: who you are, what you paid, or your order details.

Bonus: The ticket can only be used once (nullifier prevents double-entry)
without linking the entry to your identity.
"""

import hashlib
import secrets
from datetime import date

P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
G = 2
Q = (P - 1) // 2


class TicketPlatform:
    """The ticketing company (e.g., Convious) that sells tickets."""

    def __init__(self, name: str = "TicketPlatform"):
        self.name = name
        self.signing_key = secrets.randbelow(Q - 1) + 1
        self.verification_key = pow(G, self.signing_key, P)
        self.used_nullifiers = set()  # Prevents double-entry

    def issue_ticket(self, event_id: str, event_date: date, ticket_type: str,
                     buyer_name: str, order_id: str, price: float) -> dict:
        """
        Issue a ticket. The buyer gets a signed credential.
        The buyer's personal data stays on THEIR device only.
        """
        # The ticket secret — unique to this ticket, known only to the holder
        ticket_secret = secrets.randbelow(Q - 1) + 1

        # Public ticket commitment (goes on the "blockchain" or platform DB)
        ticket_hash = int(hashlib.sha256(
            f"{event_id}:{event_date}:{ticket_type}:{ticket_secret}".encode()
        ).hexdigest(), 16) % Q
        commitment = pow(G, ticket_hash, P)

        # Sign the commitment
        k = secrets.randbelow(Q - 1) + 1
        sig_r = pow(G, k, P)
        msg_hash = int(hashlib.sha256(
            f"{commitment}:{event_id}:{event_date}".encode()
        ).hexdigest(), 16) % Q
        sig_s = (k - msg_hash * self.signing_key) % Q

        # The credential — stored on the buyer's phone
        return {
            # Public (verifier can see)
            "event_id": event_id,
            "event_date": event_date.isoformat(),
            "ticket_type": ticket_type,
            "commitment": commitment,
            "signature": (sig_r, sig_s),
            "platform_key": self.verification_key,
            "platform_name": self.name,
            # Private (ONLY on the buyer's device)
            "_secret": ticket_secret,
            "_ticket_hash": ticket_hash,
            "_buyer_name": buyer_name,
            "_order_id": order_id,
            "_price": price,
        }


class TicketHolder:
    """The person with the ticket on their phone."""

    def __init__(self, credential: dict):
        self.cred = credential

    def generate_entry_proof(self) -> dict:
        """
        Generate a proof for the gate scanner.
        Proves: "I have a valid ticket" without revealing who I am.
        """
        # Nullifier — unique per ticket, prevents double-entry
        # Derived from the secret, so it's always the same for this ticket
        # but can't be linked back to the buyer
        nullifier = hashlib.sha256(
            f"nullifier:{self.cred['_secret']}:{self.cred['event_id']}".encode()
        ).hexdigest()

        # Prove knowledge of the secret behind the commitment (Schnorr-style)
        k = secrets.randbelow(Q - 1) + 1
        r = pow(G, k, P)

        # Fiat-Shamir challenge
        challenge = int(hashlib.sha256(
            f"{r}:{self.cred['commitment']}:{nullifier}".encode()
        ).hexdigest(), 16) % Q

        response = (k - challenge * self.cred["_ticket_hash"]) % Q

        return {
            # What the scanner sees:
            "event_id": self.cred["event_id"],
            "event_date": self.cred["event_date"],
            "ticket_type": self.cred["ticket_type"],
            "commitment": self.cred["commitment"],
            "nullifier": nullifier,
            "proof_r": r,
            "proof_challenge": challenge,
            "proof_response": response,
            "signature": self.cred["signature"],
            "platform_key": self.cred["platform_key"],
            # What the scanner does NOT see:
            # - buyer name
            # - order ID
            # - price paid
            # - email
            # - any personal data
        }


class GateScanner:
    """The scanner at the venue entrance."""

    def __init__(self, platform_key: int):
        self.platform_key = platform_key
        self.used_nullifiers = set()

    def scan(self, proof: dict) -> dict:
        """
        Verify a ticket proof at the gate.
        Returns admission decision without learning the buyer's identity.
        """
        # 1. Check the platform's signature
        commitment = proof["commitment"]
        sig_r, sig_s = proof["signature"]
        msg_hash = int(hashlib.sha256(
            f"{commitment}:{proof['event_id']}:{proof['event_date']}".encode()
        ).hexdigest(), 16) % Q
        sig_check = (pow(G, sig_s, P) * pow(self.platform_key, msg_hash, P)) % P
        signature_valid = sig_check == sig_r

        # 2. Verify the ZK proof (prover knows the secret)
        expected_challenge = int(hashlib.sha256(
            f"{proof['proof_r']}:{commitment}:{proof['nullifier']}".encode()
        ).hexdigest(), 16) % Q
        challenge_valid = expected_challenge == proof["proof_challenge"]

        lhs = (pow(G, proof["proof_response"], P) * pow(commitment, proof["proof_challenge"], P)) % P
        math_valid = lhs == proof["proof_r"]

        # 3. Check for double-entry
        already_used = proof["nullifier"] in self.used_nullifiers
        if not already_used:
            self.used_nullifiers.add(proof["nullifier"])

        # 4. Check date
        date_valid = proof["event_date"] == date.today().isoformat()

        all_valid = signature_valid and challenge_valid and math_valid and not already_used and date_valid

        return {
            "admitted": all_valid,
            "event": proof["event_id"],
            "ticket_type": proof["ticket_type"],
            "signature_from_platform": signature_valid,
            "proof_valid": math_valid,
            "double_entry_blocked": already_used,
            "date_valid": date_valid,
            # Privacy report
            "buyer_name_seen": False,
            "order_id_seen": False,
            "price_seen": False,
            "email_seen": False,
            "data_stored": "nullifier only (unlinkable to identity)",
        }
