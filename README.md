# ZKI-Protocol: The End of the Data Spill

## The Problem

Every time a company stores your birthdate, your home address, or your ID, they are storing a liability. When they get hacked — and [they will](https://larevuetech.fr/hackers-hit-ticketing-giant-vivaticket-disrupting-up-to-3500-venues-worldwide/) — the "spill" costs them billions and costs you your privacy.

In March 2026, a single ransomware attack disrupted 3,500 venues worldwide. Names, emails, purchase histories: all exposed. Not because the venues were careless, but because they **stored data they never needed to see**.

## The Solution

**Replace data storage with cryptographic proofs.**

ZKI-Protocol lets any person prove a fact — *I am over 18*, *I own a valid ticket*, *I live in this region* — without ever showing the raw data.

```
You keep your data on your device.
They get a mathematical "Yes" or "No."
The risk for both parties drops to zero.
```

## How It Works

### 1. Prove You Know a Secret (Schnorr ZKP)

The foundation. A bank verifies your password without ever seeing it.

```
Prover  -> Verifier: commitment (random, unique)
Verifier -> Prover:  challenge  (random number)
Prover  -> Verifier: response   (math, not the secret)
Verifier:            VERIFIED.  Secret never transmitted.
```

An impostor cannot forge the response. The math guarantees it.

### 2. Prove Your Age Without Showing Your ID

A government issues you a signed credential once (at the DMV). After that:

```
Kiosk: "Are you over 18?"
Phone: [sends ZK proof + authority signature]
Kiosk: "Verified. Welcome."

What the kiosk saw:  A mathematical proof.
What the kiosk stored: Nothing.
Your birthdate, name, address: Never left your phone.
```

### 3. Enter a Venue Without Revealing Your Identity

You buy a ticket online. At the gate:

```
Scanner: [receives proof]
Result:  "Valid Adult Day Pass for today. Admitted."

What the scanner saw:   Event, date, ticket type, cryptographic proof.
What the scanner didn't: Your name, email, order number, or what you paid.
Double entry:            Blocked (nullifier-based, unlinkable to identity).
```

## Run It

```bash
# Quick verify
python verify.py

# Full demos (password, age, ticket)
python demo.py
```

No dependencies. Python 3.8+ standard library only.

## The Three Wins

### For Companies: Liability Off-Ramping
If you don't hold personal data, you can't lose it. No data = no breach = no GDPR fine. It's cheaper to verify a proof than to secure a database.

### For People: Universal Privacy
Never fill out a form again. Your phone sees the request, checks your encrypted credentials, and sends a proof. Verified in 1 second with zero typing and zero exposure.

### For the World: Deepfake Immunity
As AI deepfakes improve, photos of IDs become meaningless. ZKI-Protocol uses mathematical attestation signed by issuing authorities. You can't deepfake a prime number.

## Comparison

| | Today (Data Storage) | ZKI (Zero-Knowledge) |
|---|---|---|
| Age check | Show full ID to stranger | Phone sends "over 18" proof |
| Buy a ticket | Name, email, address stored | Platform stores commitment |
| Enter a venue | Barcode reveals order data | Proof reveals "valid ticket" |
| Locals discount | Show utility bill | Prove "within 20km" |
| Data breach impact | Names, emails, cards leak | Only math leaks (useless) |
| GDPR compliance | Complex, expensive | No personal data = no risk |
| Deepfake risk | Fake ID photo works | Can't fake a prime number |

## Architecture

```
zkp/
  schnorr.py    Schnorr identification protocol (true ZKP)
  age.py        Age verification with Pedersen commitments
  ticket.py     Anonymous ticket entry with nullifiers
demo.py         Interactive demos
verify.py       Quick proof-of-concept
```

## The Math (simplified)

The security relies on the **discrete logarithm problem**: given `g` and `y = g^x mod p`, it is computationally infeasible to find `x`. This means:

- A prover can demonstrate knowledge of `x` through a challenge-response protocol
- A verifier can confirm the proof without ever learning `x`
- An impostor cannot guess the correct response (probability: 1/q, astronomically small)

The age and ticket proofs extend this with **Pedersen commitments** (hiding values inside math) and **Fiat-Shamir heuristic** (making interactive proofs non-interactive for real-world use).

## What's Next

- [ ] Mobile SDK (iOS/Android) for on-device credential storage
- [ ] W3C Verifiable Credentials integration
- [ ] QR code proof generation for offline verification
- [ ] Multi-credential composition ("over 18 AND valid ticket AND local resident")
- [ ] Formal security audit

## License

MIT

---

*The data you don't store is the data that can't be stolen.*
