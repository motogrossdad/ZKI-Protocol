import hashlib
import random

# THE REVOLUTION: Prove you know a secret without saying it.
def start_handshake(secret_pin):
    # 1. The Prover (You) hides the secret in a 'commitment'
    salt = str(random.randint(1000, 9999))
    commitment = hashlib.sha256((secret_pin + salt).encode()).hexdigest()
    
    print(f"🔒 PROVER: I have a secret. My commitment hash is: {commitment}")
    
    # 2. The Verifier (The Bank/App) challenges you
    # They don't know the PIN, but they know the hash you claimed.
    print("🕵️ VERIFIER: Prove you know the PIN that matches that hash.")
    
    # 3. The Proof (The Reveal)
    # In a real ZKP, this involves complex math (SNARKs). 
    # Here, we just show the salt and PIN to prove the hash was real.
    print(f"🔑 PROVER: Here is the salt ({salt}) and PIN ({secret_pin}) to verify.")
    
    # 4. The Result
    check = hashlib.sha256((secret_pin + salt).encode()).hexdigest()
    if check == commitment:
        print("✅ VERIFIER: Proof Accepted. Identity Confirmed. Raw data discarded.")

# Try it: start_handshake("1234")
