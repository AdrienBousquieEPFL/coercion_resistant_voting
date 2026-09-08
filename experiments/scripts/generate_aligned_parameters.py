#!/usr/bin/env python3
"""Generate concrete NTT primes with Q = -1 (mod t); this alone does not validate noise/security."""
import argparse
import json
import math
from pathlib import Path


def prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    # Deterministic for unsigned 64-bit integers.
    for a in (2, 325, 9375, 28178, 450775, 9780504, 1795265022):
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def find_prime(bits, step, residue, excluded):
    top = (1 << bits) - 1
    value = top - (top - residue) % step
    while value >= 1 << (bits - 1):
        if value not in excluded and prime(value):
            return value
        value -= step
    raise ValueError("no prime of the requested size in the required progression")


def generate(name, log_n, q_bits, count, p_bits, t, p_count=1):
    if not 4 <= log_n <= 20 or not 4 <= count <= 32:
        raise ValueError("unsupported ring degree or Q-prime count")
    if not 20 <= q_bits <= 60 or not 20 <= p_bits <= 61:
        raise ValueError("unsupported prime size")
    step = 2 << log_n
    if not prime(t) or (t - 1) % step:
        raise ValueError("t must be prime and support full batching at logN")
    qs = []
    for _ in range(count - 1):
        qs.append(find_prime(q_bits, step, 1, set(qs) | {t}))
    target = -pow(math.prod(qs), -1, t) % t
    residue = 1 + step * ((target - 1) * pow(step, -1, t) % t)
    qs.append(find_prime(q_bits, step * t, residue, set(qs) | {t}))
    if not 1 <= p_count <= 4:
        raise ValueError("unsupported P-prime count")
    ps = []
    for _ in range(p_count):
        ps.append(find_prime(p_bits, step, 1, set(qs + ps) | {t}))
    assert math.prod(qs) % t == t - 1
    return dict(schema_version=1, name=name, lattigo_version="v6.2.0",
                logN=log_n, Q=list(map(str, qs)), P=list(map(str, ps)), plaintext_modulus=t)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--logN", type=int, required=True)
    parser.add_argument("--q-prime-bits", type=int, required=True)
    parser.add_argument("--q-prime-count", type=int, required=True)
    parser.add_argument("--p-bits", type=int, required=True)
    parser.add_argument("--p-prime-count", type=int, default=1)
    parser.add_argument("--plaintext-modulus", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = generate(args.name, args.logN, args.q_prime_bits, args.q_prime_count,
                      args.p_bits, args.plaintext_modulus, args.p_prime_count)
    with args.output.open("x") as output:
        json.dump(result, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
