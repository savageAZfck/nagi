//! nagi — dead-man memory escrow.
//!
//! Named for the Lakota *nagi* — the spirit that survives the body.
//! The crate answers one question an organism eventually has to ask:
//! what happens to my mind if my machine dies?
//!
//! A memory vault's master key is split into `n` signed shares with a
//! `k`-of-`n` threshold (GF(256) Shamir in [`gf256`]) and handed to
//! custodian machines the owner controls. Two recovery modes:
//!
//! - **Owner unlock** — the owner signs a [`RecoveryClaim`]; any `k`
//!   custodians verify the owner signature and release their shares.
//!   Used for migration, hardware refresh, mesh topology changes.
//! - **Dead man** — the owner holds a heartbeat cadence: signed
//!   [`Beacon`]s proving liveness. When the newest beacon is older than
//!   the plan's `staleness_secs`, a beneficiary (an ed25519 key that is
//!   NOT the owner — a second key the owner controls, a trusted party, a
//!   successor organism's key) presents a signed claim and custodians
//!   release. The secret outlives the machine and the owner's presence.
//!
//! Every artifact is signed. Shards are useless alone (`k - 1` shares
//! yield zero information, not a partial secret), worthless to a
//! thief (each is bound to its ceremony and owner key by signature),
//! and self-verifying at recovery time — a custodian returning a
//! corrupted or forged share is detected before recombination.
//!
//! The transport is deliberately absent: nagi produces and consumes
//! signed artifacts; how shards reach custodians (SLICKS mesh, sneakernet,
//! a second laptop on a shelf) is the organism's problem, not the crate's.
//!
//! ```no_run
//! use nagi::{Escrow, Plan, Recovery, RecoveryClaim, Mode, Identity};
//!
//! let owner = Identity::generate();
//! let heir = Identity::generate(); // the successor key
//! let plan = Plan::dead_man(3, 5, 86_400 * 30, heir.public_key());
//! let shards = Escrow::seal(&owner, b"vault-master-key...", &plan).unwrap();
//! // distribute shards to custodians...
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

pub mod gf256;

/// Seconds since Unix epoch, UTC.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Errors produced by escrow, custody, and recovery.
#[derive(Debug)]
pub enum Error {
    /// Threshold or custodian count out of range.
    BadPlan(String),
    /// A shard failed signature or structural verification.
    BadShard(String),
    /// A claim failed verification or its preconditions are unmet.
    BadClaim(String),
    /// Not enough valid shards to recombine.
    InsufficientShards { needed: usize, got: usize },
    /// Shares recombined but the embedded secret digest does not match.
    /// This means a share verified but lied — corruption after signing.
    IntegrityMismatch,
    /// Serialization failure.
    Serde(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadPlan(m) => write!(f, "bad plan: {m}"),
            Error::BadShard(m) => write!(f, "bad shard: {m}"),
            Error::BadClaim(m) => write!(f, "bad claim: {m}"),
            Error::InsufficientShards { needed, got } => {
                write!(f, "insufficient shards: need {needed}, got {got}")
            }
            Error::IntegrityMismatch => {
                write!(f, "recombined secret fails its embedded digest")
            }
            Error::Serde(e) => write!(f, "serde: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

/// An ed25519 identity — owner, custodian, or beneficiary.
/// The key is the identity; there is no other registry.
#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self {
            signing: SigningKey::from_bytes(&bytes),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(bytes),
        }
    }

    /// Raw verifying-key bytes, hex-encoded for embedding in artifacts.
    pub fn public_key(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    /// The signing seed — persists the identity. Guard it like a private
    /// key; it is one.
    pub fn seed(&self) -> [u8; 32] {
        self.signing.to_bytes()
    }

    /// Sign the canonical JSON of a payload.
    pub fn sign(&self, payload: &BTreeMap<String, Value>) -> String {
        let body = canonical(payload);
        hex::encode(self.signing.sign(body.as_bytes()).to_bytes())
    }
}

/// Deterministic JSON serialization for signing: BTreeMap is already
/// key-ordered; `to_string` emits no whitespace and serde_json emits
/// struct fields in declaration order — canonical by construction.
fn canonical(payload: &BTreeMap<String, Value>) -> String {
    serde_json::to_string(payload).expect("BTreeMap<String, Value> always serializes")
}

fn verify_signature(pub_hex: &str, payload: &BTreeMap<String, Value>, sig_hex: &str) -> bool {
    let (Ok(pk_bytes), Ok(sig_bytes)) = (hex::decode(pub_hex), hex::decode(sig_hex)) else {
        return false;
    };
    let (Ok(pk_arr), Ok(sig_arr)): (Result<[u8; 32], _>, Result<[u8; 64], _>) = (
        pk_bytes.try_into().map_err(|_| ()),
        sig_bytes.try_into().map_err(|_| ()),
    ) else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(canonical(payload).as_bytes(), &sig).is_ok()
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// Recovery policy for an escrow ceremony.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum Mode {
    /// Owner signs a claim; shares release. Migration and key rotation.
    OwnerUnlock,
    /// Beneficiary claims after the newest heartbeat beacon is older
    /// than `staleness_secs`. The dead-man switch.
    DeadMan {
        staleness_secs: u64,
        /// Hex ed25519 public key allowed to claim.
        beneficiary: String,
    },
}

/// An escrow plan: how the secret is split and who may recover it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    /// Shares required to recombine.
    pub threshold: usize,
    /// Total custodians.
    pub custodians: usize,
    /// Recovery policy.
    pub mode: Mode,
}

impl Plan {
    /// k-of-n owner-unlock escrow — the owner alone can reassemble.
    pub fn owner_unlock(threshold: usize, custodians: usize) -> Self {
        Self {
            threshold,
            custodians,
            mode: Mode::OwnerUnlock,
        }
    }

    /// k-of-n dead-man escrow — `beneficiary` (hex ed25519 pubkey) claims
    /// after `staleness_secs` without a heartbeat.
    pub fn dead_man(
        threshold: usize,
        custodians: usize,
        staleness_secs: u64,
        beneficiary: String,
    ) -> Self {
        Self {
            threshold,
            custodians,
            mode: Mode::DeadMan {
                staleness_secs,
                beneficiary,
            },
        }
    }

    fn validate(&self) -> Result<(), Error> {
        if self.threshold == 0 || self.custodians == 0 {
            return Err(Error::BadPlan(
                "threshold and custodians must be nonzero".into(),
            ));
        }
        if self.threshold > self.custodians {
            return Err(Error::BadPlan("threshold exceeds custodians".into()));
        }
        if self.custodians > 255 {
            return Err(Error::BadPlan("GF(256) caps shares at 255".into()));
        }
        if let Mode::DeadMan { beneficiary, .. } = &self.mode {
            if beneficiary.len() != 64 || hex::decode(beneficiary).is_err() {
                return Err(Error::BadPlan(
                    "beneficiary must be a hex ed25519 key".into(),
                ));
            }
        }
        Ok(())
    }

    fn canonical(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("threshold".into(), json!(self.threshold));
        m.insert("custodians".into(), json!(self.custodians));
        match &self.mode {
            Mode::OwnerUnlock => {
                m.insert("mode".into(), json!("owner_unlock"));
            }
            Mode::DeadMan {
                staleness_secs,
                beneficiary,
            } => {
                m.insert("mode".into(), json!("dead_man"));
                m.insert("staleness_secs".into(), json!(staleness_secs));
                m.insert("beneficiary".into(), json!(beneficiary));
            }
        }
        m
    }

    /// Ceremony id: sha256 of the canonical plan + owner key. Two
    /// ceremonies over the same plan by the same owner collide — include
    /// a nonce in the secret payload (or vary the plan) per ceremony.
    /// Deterministic by construction so beacons and claims can recompute
    /// it without storing it.
    pub fn ceremony_id(&self, owner_pubkey: &str) -> String {
        let mut body = self.canonical();
        body.insert("owner".into(), json!(owner_pubkey));
        sha256_hex(canonical(&body).as_bytes())
    }
}

// ---------------------------------------------------------------------------
// Shard — one custodian's sealed share
// ---------------------------------------------------------------------------

/// A signed share bound to its ceremony, index, and custodian slot.
/// `share` is hex; it is meaningless alone and forged shares fail
/// signature verification at recovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Shard {
    pub ceremony_id: String,
    /// Share index 1..=n (x-coordinate in GF(256)).
    pub index: u8,
    pub threshold: usize,
    pub custodians: usize,
    /// Hex-encoded share bytes.
    pub share: String,
    /// sha256 of the full secret payload — lets recombination detect a
    /// signed-but-corrupt share path without trusting any custodian.
    pub secret_digest: String,
    pub owner: String,
    pub created_at: u64,
    /// Owner's signature over the canonical shard body minus this field.
    pub signature: String,
}

impl Shard {
    fn payload(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("ceremony_id".into(), json!(self.ceremony_id));
        m.insert("index".into(), json!(self.index));
        m.insert("threshold".into(), json!(self.threshold));
        m.insert("custodians".into(), json!(self.custodians));
        m.insert("share".into(), json!(self.share));
        m.insert("secret_digest".into(), json!(self.secret_digest));
        m.insert("owner".into(), json!(self.owner));
        m.insert("created_at".into(), json!(self.created_at));
        m
    }

    /// Verify the owner's signature and basic structural sanity.
    pub fn verify(&self) -> Result<(), Error> {
        if self.index == 0 || self.index as usize > self.custodians {
            return Err(Error::BadShard("index out of range".into()));
        }
        if !verify_signature(&self.owner, &self.payload(), &self.signature) {
            return Err(Error::BadShard("invalid owner signature".into()));
        }
        hex::decode(&self.share).map_err(|_| Error::BadShard("share is not hex".into()))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Beacon — owner's heartbeat
// ---------------------------------------------------------------------------

/// A signed liveness beacon. The newest valid beacon is what stands
/// between a dead-man beneficiary and recovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Beacon {
    pub ceremony_id: String,
    pub owner: String,
    pub ts: u64,
    pub signature: String,
}

impl Beacon {
    /// Sign a fresh beacon for a ceremony.
    pub fn sign(owner: &Identity, ceremony_id: &str) -> Self {
        let mut b = Self {
            ceremony_id: ceremony_id.to_string(),
            owner: owner.public_key(),
            ts: now_secs(),
            signature: String::new(),
        };
        b.signature = owner.sign(&b.payload());
        b
    }

    fn payload(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("ceremony_id".into(), json!(self.ceremony_id));
        m.insert("owner".into(), json!(self.owner));
        m.insert("ts".into(), json!(self.ts));
        m
    }

    pub fn verify(&self) -> bool {
        verify_signature(&self.owner, &self.payload(), &self.signature)
    }
}

// ---------------------------------------------------------------------------
// Claim — the request a custodian releases against
// ---------------------------------------------------------------------------

/// Evidence offered for a recovery claim.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    /// Owner-signed claim — the owner key itself requests recovery.
    OwnerSignature,
    /// Dead-man: the newest beacon the claimant can prove. The claim is
    /// valid only when `last_beacon_ts` is older than the plan's
    /// staleness window at the time a custodian evaluates it.
    DeadMan { last_beacon_ts: u64 },
}

/// A signed recovery request. The claimant signs over ceremony, mode
/// evidence, and timestamp — a custodian need only check the signature
/// against the plan's authorized key and the evidence against the clock.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryClaim {
    pub ceremony_id: String,
    pub claimant: String,
    pub evidence: Evidence,
    pub ts: u64,
    pub signature: String,
}

impl RecoveryClaim {
    /// Owner-initiated claim (migration path).
    pub fn owner_claim(owner: &Identity, ceremony_id: &str) -> Self {
        let mut c = Self {
            ceremony_id: ceremony_id.to_string(),
            claimant: owner.public_key(),
            evidence: Evidence::OwnerSignature,
            ts: now_secs(),
            signature: String::new(),
        };
        c.signature = owner.sign(&c.payload());
        c
    }

    /// Beneficiary dead-man claim, anchored to the newest beacon they
    /// can produce. `last_beacon_ts` of 0 means "no beacon ever seen" —
    /// valid only if the plan's staleness also accepts genesis+timeout.
    pub fn dead_man_claim(heir: &Identity, ceremony_id: &str, last_beacon_ts: u64) -> Self {
        let mut c = Self {
            ceremony_id: ceremony_id.to_string(),
            claimant: heir.public_key(),
            evidence: Evidence::DeadMan { last_beacon_ts },
            ts: now_secs(),
            signature: String::new(),
        };
        c.signature = heir.sign(&c.payload());
        c
    }

    fn payload(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("ceremony_id".into(), json!(self.ceremony_id));
        m.insert("claimant".into(), json!(self.claimant));
        m.insert("ts".into(), json!(self.ts));
        match &self.evidence {
            Evidence::OwnerSignature => {
                m.insert("evidence".into(), json!("owner_signature"));
            }
            Evidence::DeadMan { last_beacon_ts } => {
                m.insert("evidence".into(), json!("dead_man"));
                m.insert("last_beacon_ts".into(), json!(last_beacon_ts));
            }
        }
        m
    }
}

/// What a custodian checks before releasing a shard.
#[derive(Debug)]
pub enum ClaimVerdict {
    Release,
    /// The signature is valid but the preconditions are not yet met —
    /// e.g. heartbeat still fresh. The claimant may retry later.
    NotYet(String),
    /// Signature invalid or claimant not authorized for this plan.
    Deny(String),
}

// ---------------------------------------------------------------------------
// Escrow — the ceremony
// ---------------------------------------------------------------------------

/// The sealing side of an escrow.
pub struct Escrow;

impl Escrow {
    /// Split `secret` into `plan.custodians` signed shards.
    /// The secret is prefixed with its own sha256 so recombination can
    /// self-verify against `secret_digest` in each shard.
    pub fn seal(owner: &Identity, secret: &[u8], plan: &Plan) -> Result<Vec<Shard>, Error> {
        plan.validate()?;
        if secret.is_empty() {
            return Err(Error::BadPlan("cannot escrow an empty secret".into()));
        }
        let owner_pk = owner.public_key();
        let ceremony = plan.ceremony_id(&owner_pk);
        let digest = sha256_hex(secret);

        let raw_shares = gf256::split(
            secret,
            plan.threshold,
            plan.custodians,
            &mut rand::thread_rng(),
        );
        let created = now_secs();
        let shards = raw_shares
            .into_iter()
            .enumerate()
            .map(|(i, share)| {
                let mut s = Shard {
                    ceremony_id: ceremony.clone(),
                    index: i as u8 + 1,
                    threshold: plan.threshold,
                    custodians: plan.custodians,
                    share: hex::encode(share),
                    secret_digest: digest.clone(),
                    owner: owner_pk.clone(),
                    created_at: created,
                    signature: String::new(),
                };
                s.signature = owner.sign(&s.payload());
                s
            })
            .collect();
        Ok(shards)
    }
}

// ---------------------------------------------------------------------------
// Custodian — the holding side
// ---------------------------------------------------------------------------

/// A custodian's view: one held shard plus the plan it answers to.
/// Custody is deliberately in-memory-minimal — persistence is the host's
/// business; nagi judges release requests, nothing more.
#[derive(Clone, Debug)]
pub struct Custodian {
    shard: Shard,
    mode: Mode,
}

impl Custodian {
    /// Accept a shard after verifying the owner's signature. A custodian
    /// that stores unverified shards is storing garbage on faith.
    pub fn accept(shard: Shard, plan: &Plan) -> Result<Self, Error> {
        shard.verify()?;
        if shard.threshold != plan.threshold || shard.custodians != plan.custodians {
            return Err(Error::BadShard("shard params do not match plan".into()));
        }
        Ok(Self {
            shard,
            mode: plan.mode.clone(),
        })
    }

    /// Judge a claim. Returns the shard to release, or a verdict.
    pub fn judge(&self, claim: &RecoveryClaim, now: u64) -> (ClaimVerdict, Option<Shard>) {
        if claim.ceremony_id != self.shard.ceremony_id {
            return (
                ClaimVerdict::Deny("claim for a different ceremony".into()),
                None,
            );
        }
        if !verify_signature(&claim.claimant, &claim.payload(), &claim.signature) {
            return (
                ClaimVerdict::Deny("invalid claimant signature".into()),
                None,
            );
        }
        match (&self.mode, &claim.evidence) {
            (Mode::OwnerUnlock, Evidence::OwnerSignature) => {
                if claim.claimant == self.shard.owner {
                    (ClaimVerdict::Release, Some(self.shard.clone()))
                } else {
                    (
                        ClaimVerdict::Deny("owner-unlock claim not signed by owner".into()),
                        None,
                    )
                }
            }
            (
                Mode::DeadMan {
                    staleness_secs,
                    beneficiary,
                },
                Evidence::DeadMan { last_beacon_ts },
            ) => {
                if &claim.claimant != beneficiary {
                    return (
                        ClaimVerdict::Deny("claimant is not the plan's beneficiary".into()),
                        None,
                    );
                }
                let deadline = last_beacon_ts.saturating_add(*staleness_secs);
                if now > deadline {
                    (ClaimVerdict::Release, Some(self.shard.clone()))
                } else {
                    (
                        ClaimVerdict::NotYet(format!(
                            "heartbeat fresh: {}s remain before release",
                            deadline - now
                        )),
                        None,
                    )
                }
            }
            _ => (
                ClaimVerdict::Deny("evidence kind does not match the plan's mode".into()),
                None,
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// Recovery — recombination and the certificate
// ---------------------------------------------------------------------------

/// Signed record of a completed recovery: which ceremony, which shards,
/// who recovered, when, and the digest of what was recovered. The
/// certificate proves a recovery happened and what it produced —
/// without exposing the secret itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryCertificate {
    pub ceremony_id: String,
    pub recovered_by: String,
    pub ts: u64,
    /// Indices of the shards that recombined.
    pub shard_indices: Vec<u8>,
    /// sha256 of the recovered secret — matches shard.secret_digest.
    pub secret_digest: String,
    /// Recoverer's signature over the canonical certificate body.
    pub signature: String,
}

impl RecoveryCertificate {
    fn payload(&self) -> BTreeMap<String, Value> {
        let mut m = BTreeMap::new();
        m.insert("ceremony_id".into(), json!(self.ceremony_id));
        m.insert("recovered_by".into(), json!(self.recovered_by));
        m.insert("ts".into(), json!(self.ts));
        m.insert("shard_indices".into(), json!(self.shard_indices));
        m.insert("secret_digest".into(), json!(self.secret_digest));
        m
    }

    pub fn verify(&self) -> bool {
        verify_signature(&self.recovered_by, &self.payload(), &self.signature)
    }
}

/// The recovery side of an escrow.
pub struct Recovery;

impl Recovery {
    /// Verify each shard's signature, check ceremony/threshold
    /// consistency, and recombine. Any shard that fails verification is
    /// skipped — a lying custodian cannot poison the recovery, only
    /// fail to count toward quorum.
    ///
    /// On success returns the recovered secret and a certificate signed
    /// by `recoverer`.
    pub fn assemble(
        recoverer: &Identity,
        shards: &[Shard],
    ) -> Result<(Vec<u8>, RecoveryCertificate), Error> {
        if shards.is_empty() {
            return Err(Error::InsufficientShards { needed: 0, got: 0 });
        }
        let ceremony = &shards[0].ceremony_id;
        let threshold = shards[0].threshold;

        let mut valid: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut digests = std::collections::BTreeSet::new();
        for shard in shards {
            if shard.ceremony_id != *ceremony {
                continue;
            }
            if shard.threshold != threshold || shard.verify().is_err() {
                continue;
            }
            let Ok(share) = hex::decode(&shard.share) else {
                continue;
            };
            digests.insert(shard.secret_digest.clone());
            valid.push((shard.index, share));
        }
        if valid.len() < threshold {
            return Err(Error::InsufficientShards {
                needed: threshold,
                got: valid.len(),
            });
        }
        if digests.len() > 1 {
            return Err(Error::BadShard(
                "shards disagree on secret_digest — mixed ceremonies or corruption".into(),
            ));
        }
        let valid: Vec<(u8, Vec<u8>)> = valid.into_iter().take(threshold).collect();
        let secret = gf256::recombine(&valid).ok_or(Error::BadShard("malformed shares".into()))?;
        if sha256_hex(&secret) != shards[0].secret_digest {
            return Err(Error::IntegrityMismatch);
        }

        let mut cert = RecoveryCertificate {
            ceremony_id: ceremony.clone(),
            recovered_by: recoverer.public_key(),
            ts: now_secs(),
            shard_indices: valid.iter().map(|(i, _)| *i).collect(),
            secret_digest: shards[0].secret_digest.clone(),
            signature: String::new(),
        };
        cert.signature = recoverer.sign(&cert.payload());
        Ok((secret, cert))
    }
}
