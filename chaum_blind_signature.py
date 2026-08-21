#!/usr/bin/env python3
"""
Simple Chaum Blind Signature Demo (RSA-based)
For educational purposes only - NOT production secure.
"""

from dataclasses import dataclass
import hashlib
import secrets


@dataclass(frozen=True)
class RSAPublicKey:
    n: int
    e: int


@dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    d: int
    e: int

    def publickey(self):
        return RSAPublicKey(self.n, self.e)


def generate_rsa_keys(bits=2048):
    if bits < 32:
        raise ValueError("RSA key size must be at least 32 bits")

    public_exponent = 65537
    p_bits = bits // 2
    q_bits = bits - p_bits

    while True:
        p = generate_prime(p_bits)
        q = generate_prime(q_bits)
        if p == q:
            continue

        totient = lcm(p - 1, q - 1)
        if gcd(public_exponent, totient) != 1:
            continue

        modulus = p * q
        private_exponent = pow(public_exponent, -1, totient)
        private_key = RSAPrivateKey(modulus, private_exponent, public_exponent)
        return private_key.publickey(), private_key

def blind_message(message: bytes, pubkey):
    """Blind the message"""
    m = digest_to_int(message, pubkey.n)
    r = secrets.randbelow(pubkey.n - 2) + 2  # random blinding factor
    while gcd(r, pubkey.n) != 1:
        r = secrets.randbelow(pubkey.n - 2) + 2
    blinded = (m * pow(r, pubkey.e, pubkey.n)) % pubkey.n
    return blinded, r

def blind_sign(blinded_msg: int, privkey):
    """Signer signs blinded message"""
    signature = pow(blinded_msg, privkey.d, privkey.n)
    return signature

def unblind(signature: int, r: int, pubkey):
    """Remove blinding factor"""
    r_inv = pow(r, -1, pubkey.n)
    unblinded = (signature * r_inv) % pubkey.n
    return unblinded

def verify_signature(message: bytes, signature: int, pubkey):
    """Verify RSA signature"""
    m = digest_to_int(message, pubkey.n)
    return pow(signature, pubkey.e, pubkey.n) == m


def digest_to_int(message: bytes, modulus: int):
    digest = hashlib.sha256(message).digest()
    return int.from_bytes(digest, "big") % modulus

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def lcm(a, b):
    return abs(a * b) // gcd(a, b)


def generate_prime(bits, rounds=16):
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate, rounds=rounds):
            return candidate


def is_probable_prime(n, rounds=16):
    if n < 2:
        return False

    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31)
    for prime in small_primes:
        if n == prime:
            return True
        if n % prime == 0:
            return False

    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rounds):
        witness = secrets.randbelow(n - 3) + 2
        x = pow(witness, d, n)
        if x in (1, n - 1):
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True

if __name__ == "__main__":
    print("=== Chaum Blind Signature Demo ===\n")
    
    # Setup
    pubkey, privkey = generate_rsa_keys(1024)  # small for demo
    
    message = b"My secret vote or coin serial number"
    print(f"Original message: {message.decode()}")
    
    # Blind
    blinded, r = blind_message(message, pubkey)
    print("Message blinded and sent to signer.")
    
    # Sign
    blind_sig = blind_sign(blinded, privkey)
    print("Signer produced blind signature.")
    
    # Unblind
    signature = unblind(blind_sig, r, pubkey)
    print("Signature unblinded.")
    
    # Verify
    if verify_signature(message, signature, pubkey):
        print("✅ Signature verified successfully!")
    else:
        print("❌ Verification failed.")