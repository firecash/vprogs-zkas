use crate::Error;

/// Guest error codes carried by [`Error::Guest`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    /// Transaction protocol version is not supported by this prover build.
    VersionIncompatible = 1,
    /// Unknown exit destination tag in a journal exit entry.
    InvalidExitSpkTag = 2,
    /// `ScriptPublicKey` is not one of the supported variants (Schnorr P2PK / ECDSA P2PK / P2SH).
    InvalidExitSpk = 3,

    // --- ZKas bridge peg-out guest (see `zkas_bridge`) ---
    /// The burn attestation in `ix_data` did not decode.
    BridgeMalformedAttestation = 16,
    /// The exit receipt is not included under a burn root binding to the claimed state root.
    BridgeReceiptNotIncluded = 17,
    /// The transaction did not declare exactly one resource (the nullifier slot).
    BridgeResourceShape = 18,
    /// The declared `ResourceId` is not the attestation's exit-nullifier.
    BridgeResourceNotNullifier = 19,
    /// The nullifier slot already exists: this burn has already been exited (replay).
    BridgeReplayedExit = 20,
    /// The attestation claims a zero-value peg-out.
    BridgeZeroValue = 21,
    /// `ix_data` framing was malformed, or the canonical-`R` witness section was absent/undecodable.
    BridgeMalformedCanonicalWitness = 22,
    /// The canonical-`R` witness did not prove the claimed state root `r` is committed by Kaspa's
    /// proof-of-work (bad coinbase commitment, Merkle branch, `H_fc`, or `seq_commit`).
    BridgeCanonicalVerifyFailed = 23,
}

impl From<ErrorCode> for Error {
    fn from(e: ErrorCode) -> Self {
        Error::Guest(e as u32)
    }
}
