#!/usr/bin/env python3
"""
Quick verification — run this to see ZKI-Protocol in action.
For the full demos, run: python demo.py
"""

from zkp.schnorr import prove_knowledge

print()
print("ZKI-Protocol — Quick Verify")
print("=" * 40)
print()
print("Proving knowledge of a secret without revealing it...")
print()

result = prove_knowledge("TheRevolutionStartsHere")

print()
if result:
    print("The secret was verified. It was never transmitted.")
    print("This is Zero-Knowledge Proof.")
else:
    print("Verification failed.")
