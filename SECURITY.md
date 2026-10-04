# Security

Report vulnerabilities privately to savagetism@icloud.com — do not open
public issues for exploitable weaknesses in the escrow, custody, or
recovery paths.

Scope: GF(256) arithmetic, Shamir correctness, canonical-JSON signing,
custodian verdict logic, recovery integrity checks.

Out of scope: the transport layer delivering shards/claims/beacons, and
the host's storage of held shards — both are the integrating system's
responsibility (see THREAT_MODEL.md).
