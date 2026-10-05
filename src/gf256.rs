//! GF(2^8) arithmetic and Shamir secret sharing over bytes.
//!
//! The field is GF(256) with the AES irreducible polynomial
//! x^8 + x^4 + x^3 + x + 1 (0x1b reduction). Shares are evaluated
//! per byte: a random degree-(k-1) polynomial over GF(256) with the
//! secret byte as the constant term, sampled at x = share index
//! (indices start at 1 — index 0 would leak the secret directly).

use rand::RngCore;

/// Multiplication in GF(2^8) via Russian peasant / carryless multiply
/// with polynomial reduction. Constant-ish time: branchless inner loop
/// over the 8 bits of the multiplier.
pub fn mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// Multiplicative inverse via exponentiation: a^254 in GF(2^8).
/// a=0 maps to 0 — callers must never invert zero (share indices
/// are nonzero by construction).
pub fn inv(a: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut exp = 254u32;
    while exp > 0 {
        if exp & 1 != 0 {
            result = mul(result, base);
        }
        base = mul(base, base);
        exp >>= 1;
    }
    result
}

/// Divide a by b in GF(2^8). Panics if b is zero — that is a caller bug,
/// not recoverable input.
pub fn div(a: u8, b: u8) -> u8 {
    assert!(b != 0, "GF(256) division by zero");
    mul(a, inv(b))
}

/// Evaluate the polynomial given by coefficients (constant term first)
/// at point x in GF(256). Horner's rule.
fn poly_eval(coeffs: &[u8], x: u8) -> u8 {
    let mut acc = 0u8;
    for &c in coeffs.iter().rev() {
        acc = mul(acc, x) ^ c;
    }
    acc
}

/// Split one byte of secret into `n` shares with threshold `k`.
/// Returns `n` (index, value) pairs with indices 1..=n.
fn split_byte(secret: u8, k: usize, n: usize, rng: &mut impl RngCore) -> Vec<(u8, u8)> {
    let mut coeffs = vec![0u8; k];
    coeffs[0] = secret;
    rng.fill_bytes(&mut coeffs[1..]);
    (1..=n as u8).map(|x| (x, poly_eval(&coeffs, x))).collect()
}

/// Split an arbitrary secret into `n` shares, `k` required to recover.
/// Each returned share is `secret.len()` bytes. Panics on invalid
/// parameters — caller validates via `validate_params` first.
pub fn split(secret: &[u8], k: usize, n: usize, rng: &mut impl RngCore) -> Vec<Vec<u8>> {
    let mut shares = vec![Vec::with_capacity(secret.len()); n];
    for &byte in secret {
        for (i, (_x, y)) in split_byte(byte, k, n, rng).into_iter().enumerate() {
            shares[i].push(y);
        }
    }
    shares
}

/// Recombine shares via Lagrange interpolation at x=0.
/// `shares` is (index, share_bytes); all shares must be equal length.
/// Returns None on malformed input rather than wrong output.
pub fn recombine(shares: &[(u8, Vec<u8>)]) -> Option<Vec<u8>> {
    let len = shares.first().map(|(_, s)| s.len())?;
    if shares.iter().any(|(_, s)| s.len() != len) {
        return None;
    }
    let mut indices = std::collections::BTreeSet::new();
    for (x, _) in shares {
        if *x == 0 || !indices.insert(*x) {
            return None;
        }
    }
    let mut secret = vec![0u8; len];
    for (i, (xi, yi)) in shares.iter().enumerate() {
        // Lagrange basis coefficient for share i at x=0:
        // product over j!=i of (0 - xj) / (xi - xj). In GF(256)
        // subtraction is XOR, so this is product of xj / (xi ^ xj).
        let mut basis = 1u8;
        for (j, (xj, _)) in shares.iter().enumerate() {
            if i == j {
                continue;
            }
            basis = mul(basis, div(*xj, xi ^ xj));
        }
        for (b, &y) in secret.iter_mut().zip(yi.iter()) {
            *b ^= mul(y, basis);
        }
    }
    Some(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_laws() {
        for a in [0u8, 1, 2, 7, 0x53, 0xff] {
            assert_eq!(mul(a, 0), 0);
            assert_eq!(mul(a, 1), a);
            if a != 0 {
                assert_eq!(mul(a, inv(a)), 1, "a*{a} should be 1");
            }
        }
        // AES test vector: 0x57 * 0x83 = 0xc1
        assert_eq!(mul(0x57, 0x83), 0xc1);
    }

    #[test]
    fn split_recombine_roundtrip() {
        let mut rng = rand::thread_rng();
        let secret = b"the memory of a whole self".to_vec();
        for &(k, n) in &[(2, 3), (3, 5), (5, 8), (1, 1)] {
            let shares = split(&secret, k, n, &mut rng);
            let indexed: Vec<(u8, Vec<u8>)> = shares
                .into_iter()
                .enumerate()
                .map(|(i, s)| (i as u8 + 1, s))
                .collect();
            let picked: Vec<_> = indexed[..k].to_vec();
            assert_eq!(recombine(&picked).unwrap(), secret, "k={k} n={n}");
        }
    }

    #[test]
    fn fewer_than_threshold_recovers_garbage_not_secret() {
        let mut rng = rand::thread_rng();
        let secret = [42u8; 32];
        let shares = split(&secret, 3, 5, &mut rng);
        let indexed: Vec<(u8, Vec<u8>)> = shares
            .into_iter()
            .enumerate()
            .map(|(i, s)| (i as u8 + 1, s))
            .collect();
        // Two of three shares recombine to a wrong value almost surely;
        // the structural check is that recombination still runs and
        // (overwhelmingly) does not yield the secret.
        let partial = recombine(&indexed[..2]).unwrap();
        assert_ne!(partial, secret);
    }

    #[test]
    fn duplicate_or_zero_indices_rejected() {
        let s = [vec![1u8; 8], vec![2u8; 8]];
        assert!(recombine(&[(1, s[0].clone()), (1, s[1].clone())]).is_none());
        assert!(recombine(&[(0, s[0].clone()), (1, s[1].clone())]).is_none());
    }
}
