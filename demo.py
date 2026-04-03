#!/usr/bin/env python3
"""
ZKI-Protocol — Live Demos

Run: python demo.py
No dependencies required (stdlib only).
"""

from datetime import date, timedelta
from zkp.schnorr import prove_knowledge
from zkp.age import TrustedAuthority, AgeProver, AgeVerifier
from zkp.ticket import TicketPlatform, TicketHolder, GateScanner


def divider(title):
    print()
    print("=" * 60)
    print(f"  {title}")
    print("=" * 60)
    print()


def demo_schnorr():
    divider("DEMO 1: Prove You Know a Password (Schnorr ZKP)")
    print("  Scenario: A bank needs to verify your identity.")
    print("  Today: You type your password and they check it against their database.")
    print("  ZKI:   You prove you KNOW the password. They never see it.")
    print()

    print("  --- Attempt 1: Real password holder ---")
    result = prove_knowledge("MySecretPassword123")
    print()

    print("  --- Attempt 2: Impostor with wrong password ---")
    from zkp.schnorr import Prover, Verifier
    real_user = Prover("MySecretPassword123")
    impostor = Prover("WrongPassword")
    verifier = Verifier(real_user.public_key)  # Verifier expects real user's key

    commitment = impostor.commit()
    c = verifier.challenge()
    response = impostor.respond(c)
    valid = verifier.verify(commitment, response)

    print(f"  Public key:  {hex(real_user.public_key)[:20]}... (real user)")
    print(f"  Impostor ID: {hex(impostor.public_key)[:20]}... (different!)")
    print(f"  Result: {'VERIFIED' if valid else 'REJECTED -- impostor detected'}")
    print()
    print("  The impostor could not forge the proof.")
    print("  The real password was NEVER transmitted or stored.")


def demo_age():
    divider("DEMO 2: Prove You're Over 18 (Age Verification)")
    print("  Scenario: You want to buy wine at a self-checkout kiosk.")
    print("  Today: You show your full ID to a stranger.")
    print("  ZKI:   Your phone proves 'over 18'. They see nothing else.")
    print()

    # Setup: Government issues your credential once
    gov = TrustedAuthority("National ID Authority")
    print(f"  Trusted Authority: {gov.name}")
    print(f"  Authority Key:     {hex(gov.verification_key)[:20]}...")
    print()

    # You were born on March 15, 1990 (age 36)
    birthdate = date(1990, 3, 15)
    credential = gov.issue_credential(birthdate)
    print(f"  Your birthdate:    {birthdate}  (stored ONLY on your phone)")
    print(f"  Credential issued: Yes (signed by authority)")
    print()

    # At the kiosk: prove you're over 18
    prover = AgeProver(credential)
    proof = prover.prove_over_age(min_age=18)

    print("  --- Proof generated (this is what the kiosk sees) ---")
    print(f"  Claim:          'Person is over 18'")
    print(f"  Commitment:     {hex(proof['original_commitment'])[:20]}...")
    print(f"  Signature:      [cryptographic signature from authority]")
    print(f"  Birthdate:      NOT INCLUDED")
    print(f"  Name:           NOT INCLUDED")
    print(f"  Address:        NOT INCLUDED")
    print()

    # Kiosk verifies
    result = AgeVerifier.verify(proof)
    print("  --- Kiosk verification ---")
    for key, value in result.items():
        print(f"  {key}: {value}")

    # Also show: a minor would be rejected
    print()
    print("  --- What if a 16-year-old tries? ---")
    minor_birthdate = date(2010, 6, 1)
    minor_cred = gov.issue_credential(minor_birthdate)
    minor_prover = AgeProver(minor_cred)
    minor_proof = minor_prover.prove_over_age(min_age=18)
    print(f"  Result: {minor_proof}")


def demo_ticket():
    divider("DEMO 3: Enter a Theme Park (Ticket Verification)")
    print("  Scenario: You bought a ticket to Jungle City online.")
    print("  Today: Scanner reads your barcode -> sees your name, order, email.")
    print("  ZKI:   Scanner gets a proof -> sees 'valid ticket'. Nothing else.")
    print()

    # Setup: Ticketing platform
    platform = TicketPlatform("Convious")
    print(f"  Platform:     {platform.name}")
    print()

    # Buy a ticket (personal data stored on YOUR phone only)
    today = date.today()
    credential = platform.issue_ticket(
        event_id="jungle-city-general",
        event_date=today,
        ticket_type="Adult Day Pass",
        buyer_name="Marie Dupont",
        order_id="ORD-2026-48291",
        price=29.50,
    )

    print("  --- Ticket purchased ---")
    print(f"  Buyer:       Marie Dupont   (on HER phone only)")
    print(f"  Order:       ORD-2026-48291 (on HER phone only)")
    print(f"  Price:       EUR 29.50       (on HER phone only)")
    print(f"  Event:       {credential['event_id']}")
    print(f"  Date:        {credential['event_date']}")
    print(f"  Type:        {credential['ticket_type']}")
    print()

    # At the gate
    holder = TicketHolder(credential)
    gate = GateScanner(platform.verification_key)

    print("  --- At the gate: first scan ---")
    proof = holder.generate_entry_proof()
    result = gate.scan(proof)
    for key, value in result.items():
        print(f"  {key}: {value}")

    # Try to enter again (double-entry attempt)
    print()
    print("  --- Second scan (same ticket) ---")
    proof2 = holder.generate_entry_proof()
    result2 = gate.scan(proof2)
    print(f"  admitted: {result2['admitted']}")
    print(f"  double_entry_blocked: {result2['double_entry_blocked']}")
    print(f"  (Ticket used once. Can't sneak in twice.)")


def demo_comparison():
    divider("COMPARISON: Today vs. ZKI-Protocol")
    print("""
  +-----------------------+----------------------------+---------------------------+
  |                       |  TODAY (Data Storage)       |  ZKI (Zero-Knowledge)     |
  +-----------------------+----------------------------+---------------------------+
  | Age check             | Show full ID to stranger   | Phone sends "over 18" proof|
  | Buy a ticket          | Name, email, address stored | Platform stores commitment |
  | Enter a venue         | Barcode -> full order data | Proof -> "valid ticket"    |
  | Locals discount       | Show utility bill          | Prove "within 20km"        |
  | Data breach impact    | Names, emails, cards leak  | Only math leaks (useless)  |
  | GDPR compliance       | Complex, expensive         | No personal data = no risk |
  | Deepfake risk         | Fake ID photo works        | Can't fake a prime number  |
  +-----------------------+----------------------------+---------------------------+

  The data you don't store is the data that can't be stolen.
    """)


if __name__ == "__main__":
    print()
    print("  ZKI-Protocol: The End of the Data Spill")
    print("  ========================================")
    print("  Running all demos...")

    demo_schnorr()
    demo_age()
    demo_ticket()
    demo_comparison()

    divider("ALL DEMOS COMPLETE")
    print("  Every verification above was done WITHOUT revealing private data.")
    print("  No birthdate. No name. No address. No order number. No email.")
    print("  Just math.")
    print()
