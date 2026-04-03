"""
Schnorr Zero-Knowledge Proof

This is a REAL zero-knowledge proof. The prover convinces the verifier
that they know a secret number, without ever revealing it.

How it works (simplified):
- There's a large prime number p and a generator g (public, shared)
- The prover has a secret x
- The prover publishes y = g^x mod p (public key)
- The verifier challenges: "prove you know x without telling me x"
- The prover responds with a calculated value that ONLY someone
  who knows x could produce — but the value itself doesn't reveal x

This is the foundation of digital signatures, cryptocurrency wallets,
and modern authentication.
"""

import hashlib
import secrets


# Public parameters (in production, use standardized curve parameters)
# Using a safe prime for simplicity
P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
G = 2
Q = (P - 1) // 2  # Order of the subgroup


class Prover:
    """The person who wants to prove they know a secret."""

    def __init__(self, secret: str):
        # Convert secret string to a number
        self.x = int(hashlib.sha256(secret.encode()).hexdigest(), 16) % Q
        # Public key: y = g^x mod p
        self.public_key = pow(G, self.x, P)

    def commit(self):
        """Step 1: Create a random commitment."""
        self.k = secrets.randbelow(Q - 1) + 1  # random nonce
        self.r = pow(G, self.k, P)  # commitment
        return self.r

    def respond(self, challenge: int) -> int:
        """Step 3: Respond to the challenge WITHOUT revealing the secret."""
        # s = k - challenge * x (mod q)
        # This value is useless without knowing k, which was random
        s = (self.k - challenge * self.x) % Q
        return s


class Verifier:
    """The party who wants to verify — without learning the secret."""

    def __init__(self, public_key: int):
        self.public_key = public_key

    def challenge(self) -> int:
        """Step 2: Send a random challenge."""
        self.c = secrets.randbelow(Q - 1) + 1
        return self.c

    def verify(self, commitment: int, response: int) -> bool:
        """Step 4: Check the proof. Returns True/False — never sees the secret."""
        # Verify: g^s * y^c == r (mod p)
        # This equation ONLY holds if the prover knew x
        lhs = (pow(G, response, P) * pow(self.public_key, self.c, P)) % P
        return lhs == commitment


def prove_knowledge(secret: str, verbose: bool = True) -> bool:
    """
    Complete Schnorr ZKP flow.
    The prover demonstrates knowledge of `secret` without revealing it.
    """
    # Setup
    prover = Prover(secret)
    verifier = Verifier(prover.public_key)

    if verbose:
        print(f"  Public key: {hex(prover.public_key)[:20]}...")
        print(f"  Secret:     [NEVER TRANSMITTED]")
        print()

    # Run the protocol
    # Step 1: Prover commits
    commitment = prover.commit()
    if verbose:
        print(f"  1. Prover  -> Verifier: commitment = {hex(commitment)[:20]}...")

    # Step 2: Verifier challenges
    c = verifier.challenge()
    if verbose:
        print(f"  2. Verifier -> Prover:  challenge  = {hex(c)[:20]}...")

    # Step 3: Prover responds
    response = prover.respond(c)
    if verbose:
        print(f"  3. Prover  -> Verifier: response   = {hex(response)[:20]}...")

    # Step 4: Verifier checks
    valid = verifier.verify(commitment, response)
    if verbose:
        print()
        print(f"  Result: {'VERIFIED' if valid else 'REJECTED'}")
        print(f"  Secret revealed: NO")

    return valid
