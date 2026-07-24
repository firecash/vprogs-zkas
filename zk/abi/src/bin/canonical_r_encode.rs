//! Turns the `--emit` output of `canonical-r-probe` into peg-out `ix_data`.
//!
//! The probe runs against a live ZKas node (it pins the node fork for the witness RPC); this side
//! owns the wire encoder, so the two together form the relayer without duplicating either half.
//! Reads `key=value` lines on stdin, rebuilds the [`OwnedCanonicalRWitness`], self-checks it with
//! [`OwnedCanonicalRWitness::verify_direct`] against the `R` in the member coinbase, and prints the
//! encoded `ix_data` as hex.
//!
//! Usage: `canonical-r-probe 127.0.0.1:16110 200 --emit | canonical-r-encode`

use std::io::Read;

use vprogs_zk_abi::canonical_r::{OwnedCanonicalRWitness, SHIELDED_COMMITMENT_OFFSET};

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap_or_else(|e| fatal(&format!("read stdin: {e}")));

    let mut queried_block = None;
    let mut member_block = None;
    let mut member_payload = None;
    let mut member_blue_work = None;
    let mut leaf_index = 0u32;
    let mut other_leaves = Vec::new();
    let mut activity_root = None;
    let mut context_hash = None;
    let mut parent_seq_commit = None;
    let mut seq_commit = None;

    for line in input.lines() {
        let Some((key, value)) = line.trim().split_once('=') else { continue };
        match key {
            "queried_block" => queried_block = Some(hash32(value)),
            "member_block" => member_block = Some(hash32(value)),
            "member_payload" => member_payload = Some(unhex(value)),
            "member_blue_work" => member_blue_work = Some(unhex(value)),
            "leaf_index" => leaf_index = value.parse().unwrap_or_else(|_| fatal("bad leaf_index")),
            "other_leaf" => other_leaves.push(hash32(value)),
            "activity_root" => activity_root = Some(hash32(value)),
            "context_hash" => context_hash = Some(hash32(value)),
            "parent_seq_commit" => parent_seq_commit = Some(hash32(value)),
            "seq_commit" => seq_commit = Some(hash32(value)),
            _ => {}
        }
    }

    let member_payload = member_payload.unwrap_or_else(|| fatal("missing member_payload"));
    let r: [u8; 32] = member_payload
        .get(SHIELDED_COMMITMENT_OFFSET..SHIELDED_COMMITMENT_OFFSET + 32)
        .and_then(|s| s.try_into().ok())
        .unwrap_or_else(|| fatal("member payload too short to carry R at offset 16"));

    // The two-chain-only fields are unused on the single-chain path; they stay empty/zero.
    let owned = OwnedCanonicalRWitness {
        coinbase_version: 0,
        coinbase_outputs: Vec::new(),
        coinbase_lock_time: 0,
        coinbase_subnetwork: [0u8; 20],
        coinbase_gas: 0,
        coinbase_payload: Vec::new(),
        coinbase_branch: Vec::new(),
        header_version: 0,
        header_parents: Vec::new(),
        hash_merkle_root: [0u8; 32],
        accepted_id_merkle_root: [0u8; 32],
        utxo_commitment: [0u8; 32],
        timestamp: 0,
        bits: 0,
        nonce: 0,
        daa_score: 0,
        blue_score: 0,
        header_blue_work_be: Vec::new(),
        pruning_point: [0u8; 32],
        kaspa_payload: member_payload,
        kaspa_block_hash: queried_block.unwrap_or_else(|| fatal("missing queried_block")),
        kaspa_blue_work_be: member_blue_work.unwrap_or_else(|| fatal("missing member_blue_work")),
        other_leaves,
        leaf_index,
        activity_root: activity_root.unwrap_or_else(|| fatal("missing activity_root")),
        context_hash: context_hash.unwrap_or_else(|| fatal("missing context_hash")),
        parent_seq_commit: parent_seq_commit.unwrap_or_else(|| fatal("missing parent_seq_commit")),
        seq_commit: seq_commit.unwrap_or_else(|| fatal("missing seq_commit")),
        member_block_hash: member_block.unwrap_or_else(|| fatal("missing member_block")),
    };

    let proof = owned.verify_direct(&r).unwrap_or_else(|e| fatal(&format!("verify_direct: {e:?}")));
    if proof.seq_commit.as_bytes() != owned.seq_commit {
        fatal("recomputed seq_commit does not match the probe's value");
    }

    // Round-trip through the wire and re-verify, so what is printed is exactly what the guest will
    // decode and accept, not merely an in-memory struct that happened to verify.
    let ix_data = owned.encode();
    let decoded = OwnedCanonicalRWitness::decode(&ix_data).unwrap_or_else(|| fatal("own ix_data failed to decode"));
    let decoded_proof = decoded.verify_direct(&r).unwrap_or_else(|e| fatal(&format!("decoded verify_direct: {e:?}")));
    if decoded_proof != proof {
        fatal("decoded witness proves a different (seq_commit, block) pair");
    }

    eprintln!("R              : {}", hex(&r));
    eprintln!("seq_commit     : {}", hex(&proof.seq_commit.as_bytes()));
    eprintln!("queried block  : {}", hex(&proof.kaspa_block_hash.as_bytes()));
    eprintln!("ix_data        : {} bytes", ix_data.len());
    eprintln!("OK: encoded ix_data decodes and verifies; bytes follow on stdout");
    println!("{}", hex(&ix_data));
}

/// Decodes a lowercase-hex string, aborting on any non-hex input.
fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        fatal("odd-length hex");
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or_else(|_| fatal("bad hex")))
        .collect()
}

/// Decodes a 32-byte hex hash.
fn hash32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap_or_else(|_| fatal("expected a 32-byte hex value"))
}

/// Lowercase hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Prints `msg` to stderr and exits non-zero.
fn fatal(msg: &str) -> ! {
    eprintln!("canonical-r-encode: {msg}");
    std::process::exit(1);
}
