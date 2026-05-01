from __future__ import annotations

from dataclasses import dataclass
import secrets
from typing import Sequence


@dataclass(frozen=True)
class PublicParameters:
    G: dict[str, int | str]
    F: dict[str, int | str]
    g: int
    h: int


@dataclass(frozen=True)
class Commitment:
    values: tuple[int, ...]


@dataclass(frozen=True)
class Witness:
    blinding_polynomial: tuple[int, ...]


def Setup(q: int ) -> PublicParameters:
    if not _is_prime(q):
        raise ValueError("q must be prime.")

    p = _find_group_modulus(q)
    print("group mod p" + str(p))
    g, h = _sample_independent_generators(p, q)
    print("g: " + str(g))
    print("h: " + str(h))
    
    return PublicParameters(
        G={
            "type": "prime_order_subgroup_mod_p",
            "modulus": p,
            "order": q,
        },
        F={
            "type": "finite_field_mod_q",
            "modulus": q,
        },
        g=g,
        h=h,
    )

def Commit(
    pp: PublicParameters,
    polynomial: Sequence[int],
    n: int,
) -> tuple[Commitment, Witness]:
    q = _field_modulus(pp)
    coeffs = _normalize_polynomial(polynomial, q)

    if n <= 0:
        raise ValueError("n must be positive.")
    if n >= q:
        raise ValueError("n must be smaller than the field modulus.")

    degree = _polynomial_degree(coeffs)
    blind_coeffs = _random_polynomial(degree, q) # generates the other random polynomial r(.)
    print("blinding polynomial: " + str(tuple(blind_coeffs)))

    values = tuple(
        _pedersen_commit(
            pp,
            _evaluate_polynomial(coeffs, i, q),
            _evaluate_polynomial(blind_coeffs, i, q),
        )
        for i in range(1, n + 1)
    )
    print("values: " + str(values))
    print("blinding polynomial: " + str(tuple(blind_coeffs)))

    return Commitment(values), Witness(tuple(blind_coeffs))


def Open(
    pp: PublicParameters,
    witness: Witness,
    polynomial: Sequence[int],
    i: int,
) -> tuple[int, int]:
    q = _field_modulus(pp)
    s = _normalize_polynomial(polynomial, q)
    r = _normalize_polynomial(witness.blinding_polynomial, q)

    u = _evaluate_polynomial(s, i, q)
    pi = _evaluate_polynomial(r, i, q)

    return u, pi


def BatchOpen(
    pp: PublicParameters,
    polynomial: Sequence[int],
    indices: Sequence[int],
    witness: Witness,
) -> tuple[tuple[int, ...], tuple[int, ...]]:
    q = _field_modulus(pp)
    s = _normalize_polynomial(polynomial, q)
    r = _normalize_polynomial(witness.blinding_polynomial, q)

    shares = tuple(_evaluate_polynomial(s, i, q) for i in indices)
    proofs = tuple(_evaluate_polynomial(r, i, q) for i in indices)

    return shares, proofs


def Verify(
    pp: PublicParameters,
    commitment: Commitment,
    i: int,
    u: int,
    pi: int,
) -> bool:
    return commitment.values[i - 1] == _pedersen_commit(pp, u, pi)


def BatchVerify(
    pp: PublicParameters,
    commitment: Commitment,
    indices: Sequence[int],
    shares: Sequence[int],
    proofs: Sequence[int],
) -> bool:
    k = len(indices)
    if k != len(shares) or k != len(proofs):
        return False

    q = _field_modulus(pp)
    p = _group_modulus(pp)
    gammas = [secrets.randbelow(q) for _ in range(k)]

    folded_share = 0
    folded_proof = 0
    left = 1

    for gamma, index, share, proof in zip(gammas, indices, shares, proofs):
        folded_share = (folded_share + gamma * share) % q
        folded_proof = (folded_proof + gamma * proof) % q
        left = (left * pow(commitment.values[index - 1], gamma, p)) % p

    right = _pedersen_commit(pp, folded_share, folded_proof)
    return left == right


def DegCheck(
    pp: PublicParameters,
    commitment: Commitment,
    degree: int,
) -> bool:
    n = len(commitment.values)
    q = _field_modulus(pp)
    p = _group_modulus(pp)
    z = _random_polynomial(n - degree - 2, q)

    result = 1
    for i, value in enumerate(commitment.values, start=1):
        exponent = (_evaluate_polynomial(z, i, q) * _lagrange_weight(i, n, q)) % q
        result = (result * pow(value, exponent, p)) % p

    return result == 1


def _field_modulus(pp: PublicParameters) -> int:
    return int(pp.F["modulus"])


def _group_modulus(pp: PublicParameters) -> int:
    return int(pp.G["modulus"])


def _pedersen_commit(pp: PublicParameters, value: int, blinding: int) -> int:
    p = _group_modulus(pp)
    q = _field_modulus(pp)
    return (pow(pp.g, value % q, p) * pow(pp.h, blinding % q, p)) % p


def _random_polynomial(degree: int, modulus: int) -> list[int]:
    if degree < 0:
        raise ValueError("degree must be non-negative.")
    return [secrets.randbelow(modulus) for _ in range(degree + 1)]


def _normalize_polynomial(coefficients: Sequence[int], modulus: int) -> list[int]:
    coeffs = [coefficient % modulus for coefficient in coefficients]
    while len(coeffs) > 1 and coeffs[-1] == 0:
        coeffs.pop()
    return coeffs or [0]


def _polynomial_degree(coefficients: Sequence[int]) -> int:
    coeffs = list(coefficients)
    while len(coeffs) > 1 and coeffs[-1] == 0:
        coeffs.pop()
    return len(coeffs) - 1


def _evaluate_polynomial(coefficients: Sequence[int], x: int, modulus: int) -> int:
    result = 0
    point = x % modulus
    for coefficient in reversed(coefficients):
        result = (result * point + coefficient) % modulus
    return result


def _lagrange_weight(i: int, n: int, modulus: int) -> int:
    result = 1
    for j in range(1, n + 1):
        if j != i:
            result = (result * _mod_inverse(i - j, modulus)) % modulus
    return result


def _mod_inverse(value: int, modulus: int) -> int:
    return pow(value % modulus, -1, modulus)


def _sample_independent_generators(p: int, q: int) -> tuple[int, int]:
    g = _sample_subgroup_generator(p, q)
    h = _sample_subgroup_generator(p, q, exclude={g})
    return g, h


def _sample_subgroup_generator(p: int, q: int, exclude: set[int] | None = None) -> int:
    excluded = exclude or set()
    cofactor = (p - 1) // q

    while True:
        candidate = pow(secrets.randbelow(p - 3) + 2, cofactor, p)
        if candidate == 1 or candidate in excluded:
            continue
        if pow(candidate, q, p) == 1:
            return candidate


def _find_group_modulus(q: int) -> int:
    multiplier = 2
    while True:
        p = multiplier * q + 1
        if _is_prime(p):
            return p
        multiplier += 1


def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    divisor = 3
    while divisor * divisor <= n:
        if n % divisor == 0:
            return False
        divisor += 2
    return True
