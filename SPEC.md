# SPEC — nagi v0.1

## Secret sharing

Shamir over GF(2^8), AES polynomial (0x1b). For each secret byte, a random
degree-(k-1) polynomial with the byte as constant term is sampled at
x = 1..=n. Share index 0 is never emitted (f(0) = secret). Recombination
is Lagrange interpolation at x=0 over any k valid shares.

## Canonical signing

Every signed artifact's payload is canonical JSON: `BTreeMap<String,
Value>` serialized by serde_json (key-ordered, no whitespace). The
signature field is excluded from its own payload. Signatures are
ed25519 over the canonical bytes.

## Artifacts

### Shard

```json
{
  "ceremony_id": "hex64",
  "index": 1,
  "threshold": 3,
  "custodians": 5,
  "share": "hex",
  "secret_digest": "sha256 hex of the full secret",
  "owner": "hex ed25519 pubkey",
  "created_at": 1700000000,
  "signature": "hex ed25519 sig over all fields above"
}
```

`ceremony_id = sha256(canonical(plan) + owner_pubkey)`. `secret_digest`
lets recombination detect a signed-but-corrupt share: a signature proves
the owner emitted it, not that transport preserved it.

### Beacon

```json
{ "ceremony_id": "hex64", "owner": "hex", "ts": 1700000000, "signature": "hex" }
```

### RecoveryClaim

```json
{
  "ceremony_id": "hex64",
  "claimant": "hex",
  "evidence": { "kind": "owner_signature" } ,
  "ts": 1700000000,
  "signature": "hex"
}
```

Dead-man evidence: `{ "kind": "dead_man", "last_beacon_ts": 1700000000 }`.

### RecoveryCertificate

```json
{
  "ceremony_id": "hex64",
  "recovered_by": "hex",
  "ts": 1700000000,
  "shard_indices": [1, 3, 4],
  "secret_digest": "sha256 hex",
  "signature": "hex"
}
```

## Custodian verdict

`judge(claim, now)` returns:

- `Release` + shard — signature valid, claimant authorized, preconditions met
- `NotYet` — valid claim, heartbeat still fresh; remaining seconds reported
- `Deny` — bad signature, wrong claimant, or evidence/mode mismatch

Custodians evaluate the dead-man clock themselves. The claimant provides
the newest beacon they can prove; honesty is enforced because an earlier
`last_beacon_ts` only tightens the wait, never loosens it — a claimant
who lies about staleness must forge the owner's signature on a stale
beacon, which is unforgeable. Claiming `0` (no beacon ever) is valid only
when `0 + staleness_secs < now`.

## Recovery integrity

`Recovery::assemble` drops any shard that fails signature verification,
then requires: all surviving shards share one ceremony_id, one threshold,
and one secret_digest; count ≥ threshold. After recombination the secret
is hashed and compared to `secret_digest` — catching the case where a
validly-signed share was corrupted after emission.

## Limits

- 255 custodians max (GF(256) index space).
- Dead-man timestamps rely on custodian clocks; sub-second skew is
  irrelevant at day-scale staleness windows.
- The crate does not encrypt shards at rest — custody protection is the
  host's job (nagi shards are information-theoretically safe alone anyway:
  they reveal nothing until threshold).
