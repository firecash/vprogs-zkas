//! Shielded-pool end-to-end demo.
//!
//! Runs the full product loop against the REAL RISC0 spend guest:
//!   1. Alice and Charlie deposit KAS (transparent edge, recipient hidden from block one);
//!      Alice migrates ZKAS in (burn-and-mint, simulated at the edge in this demo).
//!   2. Alice pays Bob privately — fee in ZKAS, credited to the relayer.
//!   3. Charlie (KAS-only) pays Alice privately — fee in KAS at the 3x premium.
//!   4. Bob exits KAS back to L1 (public by definition).
//!
//! After every transaction it prints EXACTLY what each party can see: the L1 observer (journal
//! + ciphertext bytes only), the relayer, the recipient (trial decryption), and the wallets.
//!
//! `RISC0_DEV_MODE=1` (default here) executes the guest for real with a fake seal; pass
//! `--real` to produce and verify a genuine STARK.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use risc0_zkvm::{default_prover, ExecutorEnv};
use std::collections::HashSet;
use vprogs_shielded_demo_types::sha2::{Digest, Sha256};
use vprogs_shielded_demo_types::{
    addr_from_sk, batch_state, deposit_rho, nf_default_ladder, nk_from_sk, node_hash, note_cm,
    nullifier, output_rho, verify_batch, zero_ladder, BatchTxWitness, BatchWitness, ExitDecl,
    Frontier, Note, ShieldedTxJournal, ShieldedTxWitness, SparseNfSet, SpendWitness, ASSET_KAS,
    ASSET_ZKAS, KAS_FEE_PREMIUM, MIN_FEE_ZKAS, NF_DEPTH, TREE_DEPTH,
};
use x25519_dalek::{PublicKey, StaticSecret};

mod l1;

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut d = Sha256::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().into()
}

fn kdf(shared: &[u8; 32]) -> Key {
    Key::from(hash_parts(&[b"zkasL2.enc.key", shared]))
}

const UNIT: u64 = 100_000_000; // 1 KAS/ZKAS = 1e8 base units, like sompi

fn short(b: &[u8]) -> String {
    format!("{}…", hex::encode(&b[..4]))
}

fn fmt_amt(v: u64) -> String {
    format!("{}.{:08}", v / UNIT, v % UNIT)
}

fn asset_name(a: u8) -> &'static str {
    if a == ASSET_KAS {
        "KAS"
    } else {
        "ZKAS"
    }
}

// ---------------------------------------------------------------------------------------------
// Actors
// ---------------------------------------------------------------------------------------------

struct Actor {
    name: &'static str,
    sk: [u8; 32],
    enc_sk: StaticSecret,
}

impl Actor {
    fn new(name: &'static str) -> Self {
        let mut sk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sk);
        let enc_sk = StaticSecret::from(hash_parts(&[b"zkasL2.enc.sk", &sk]));
        Actor { name, sk, enc_sk }
    }
    fn pk(&self) -> [u8; 32] {
        addr_from_sk(&self.sk)
    }
    fn enc_pk(&self) -> PublicKey {
        PublicKey::from(&self.enc_sk)
    }
}

// ---------------------------------------------------------------------------------------------
// Note encryption: epk(32) ‖ nonce(12) ‖ AEAD(note bytes)
// ---------------------------------------------------------------------------------------------

fn note_bytes(n: &Note) -> Vec<u8> {
    let mut v = Vec::with_capacity(105);
    v.push(n.asset);
    v.extend_from_slice(&n.value.to_le_bytes());
    v.extend_from_slice(&n.pk);
    v.extend_from_slice(&n.rho);
    v.extend_from_slice(&n.rseed);
    v
}

fn note_from_bytes(b: &[u8]) -> Option<Note> {
    if b.len() != 105 {
        return None;
    }
    Some(Note {
        asset: b[0],
        value: u64::from_le_bytes(b[1..9].try_into().ok()?),
        pk: b[9..41].try_into().ok()?,
        rho: b[41..73].try_into().ok()?,
        rseed: b[73..105].try_into().ok()?,
    })
}

fn encrypt_note(note: &Note, to: &PublicKey) -> Vec<u8> {
    let esk = StaticSecret::random_from_rng(rand::thread_rng());
    let epk = PublicKey::from(&esk);
    let shared = esk.diffie_hellman(to);
    let cipher = ChaCha20Poly1305::new(&kdf(shared.as_bytes()));
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), note_bytes(note).as_slice()).expect("aead");
    let mut out = Vec::with_capacity(32 + 12 + ct.len());
    out.extend_from_slice(epk.as_bytes());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn try_decrypt(actor: &Actor, ct: &[u8]) -> Option<Note> {
    if ct.len() < 44 {
        return None;
    }
    let epk = PublicKey::from(<[u8; 32]>::try_from(&ct[..32]).ok()?);
    let shared = actor.enc_sk.diffie_hellman(&epk);
    let cipher = ChaCha20Poly1305::new(&kdf(shared.as_bytes()));
    let pt = cipher.decrypt(Nonce::from_slice(&ct[32..44]), &ct[44..]).ok()?;
    note_from_bytes(&pt)
}

// ---------------------------------------------------------------------------------------------
// The pool (what rollup nodes derive from L1 data)
// ---------------------------------------------------------------------------------------------

struct Pool {
    zeros: [[u8; 32]; TREE_DEPTH + 1],
    leaves: Vec<[u8; 32]>,
    /// Frontier mirror of `leaves` (the batch witness state representation).
    frontier: Frontier,
    /// History-wide nullifier accumulator (per-insert witnesses feed the batch proof).
    nf_acc: SparseNfSet,
    /// Batch under construction: deposits + receipt-backed tx witnesses.
    batch_deposits: Vec<[u8; 32]>,
    batch_txs: Vec<BatchTxWitness>,
    /// Every historical root (demo stand-in for the settled-anchor window).
    roots: HashSet<[u8; 32]>,
    nullifiers: HashSet<[u8; 32]>,
    /// The public ciphertext ledger, exactly as it would sit in L1 payloads.
    ledger: Vec<(u32, Vec<u8>)>, // (leaf index of the cm, ciphertext)
    relayer_earned: [u64; 2],
    exits: Vec<ExitDecl>,
}

impl Pool {
    fn new() -> Self {
        let zeros = zero_ladder();
        let mut p = Pool {
            zeros,
            leaves: Vec::new(),
            frontier: Frontier::default(),
            nf_acc: SparseNfSet::default(),
            batch_deposits: Vec::new(),
            batch_txs: Vec::new(),
            roots: HashSet::new(),
            nullifiers: HashSet::new(),
            ledger: Vec::new(),
            relayer_earned: [0, 0],
            exits: Vec::new(),
        };
        p.roots.insert(p.root());
        p
    }

    fn root(&self) -> [u8; 32] {
        let mut level = self.leaves.clone();
        for d in 0..TREE_DEPTH {
            if level.is_empty() {
                return self.zeros[TREE_DEPTH];
            }
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let l = pair[0];
                let r = *pair.get(1).unwrap_or(&self.zeros[d]);
                next.push(node_hash(&l, &r));
            }
            level = next;
        }
        level[0]
    }

    fn path(&self, target: u32) -> Vec<[u8; 32]> {
        let mut path = Vec::with_capacity(TREE_DEPTH);
        let mut level = self.leaves.clone();
        let mut idx = target;
        for d in 0..TREE_DEPTH {
            let sib = idx ^ 1;
            path.push(*level.get(sib as usize).unwrap_or(&self.zeros[d]));
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for pair in level.chunks(2) {
                let l = pair[0];
                let r = *pair.get(1).unwrap_or(&self.zeros[d]);
                next.push(node_hash(&l, &r));
            }
            level = next;
            idx >>= 1;
        }
        path
    }

    fn add_leaf(&mut self, cm: [u8; 32], ciphertext: Vec<u8>) -> u32 {
        let idx = self.leaves.len() as u32;
        self.leaves.push(cm);
        self.frontier.push(cm);
        self.ledger.push((idx, ciphertext));
        let r = self.root();
        self.roots.insert(r);
        idx
    }

    /// Apply a VERIFIED journal — the rollup node's state transition.
    fn apply(&mut self, j: &ShieldedTxJournal, ciphertexts: Vec<Vec<u8>>) {
        assert!(self.roots.contains(&j.anchor), "unknown anchor");
        let mut nf_siblings = Vec::with_capacity(j.nullifiers.len());
        for nf in &j.nullifiers {
            assert!(self.nullifiers.insert(*nf), "double spend");
            nf_siblings.push(self.nf_acc.insert(nf).expect("accumulator replay"));
        }
        self.batch_txs.push(BatchTxWitness { journal: j.clone(), nf_siblings });
        for (cm, ct) in j.new_cms.iter().zip(ciphertexts) {
            self.add_leaf(*cm, ct);
        }
        self.relayer_earned[j.fee_asset as usize] += j.fee_amount;
        if let Some(e) = j.exit {
            self.exits.push(e);
        }
    }

    /// A wallet's view: trial-decrypt the whole public ledger with this actor's key.
    fn scan(&self, actor: &Actor) -> Vec<(Note, u32, bool)> {
        let nk = nk_from_sk(&actor.sk);
        let mut found = Vec::new();
        for (leaf, ct) in &self.ledger {
            if let Some(note) = try_decrypt(actor, ct) {
                if note_cm(&note) == self.leaves[*leaf as usize] {
                    let spent = self.nullifiers.contains(&nullifier(&nk, &note.rho));
                    found.push((note, *leaf, spent));
                }
            }
        }
        found
    }

    fn balance(&self, actor: &Actor) -> [u64; 2] {
        let mut b = [0u64; 2];
        for (n, _, spent) in self.scan(actor) {
            if !spent {
                b[n.asset as usize] += n.value;
            }
        }
        b
    }
}

// ---------------------------------------------------------------------------------------------
// Proving
// ---------------------------------------------------------------------------------------------

struct GuestProver {
    elf: Vec<u8>,
    image_id: risc0_zkvm::Digest,
}

impl GuestProver {
    fn load() -> Self {
        let path = std::env::var("SHIELDED_POOL_ELF").unwrap_or_else(|_| {
            format!(
                "{}/../../zk/backend/risc0/shielded-pool/compiled/program.elf",
                env!("CARGO_MANIFEST_DIR")
            )
        });
        let raw = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("cannot read guest ELF at {path}: {e}"));
        // Wrap the raw user ELF with the trusted v1compat kernel, exactly like the production
        // pipeline's ElfBinary does — the image id commits kernel + guest together.
        let binary = risc0_binfmt::ProgramBinary::new(&raw, risc0_zkos_v1compat::V1COMPAT_ELF);
        let image_id = binary.compute_image_id().expect("image id");
        let elf = binary.encode();
        GuestProver { elf, image_id }
    }

    fn prove(&self, w: &ShieldedTxWitness) -> (ShieldedTxJournal, u64, risc0_zkvm::Receipt) {
        let env = ExecutorEnv::builder().write(w).expect("ser").build().expect("env");
        let info = default_prover().prove(env, &self.elf).expect("proving failed");
        info.receipt.verify(self.image_id).expect("receipt does not verify");
        let journal: ShieldedTxJournal = info.receipt.journal.decode().expect("journal");
        (journal, info.stats.total_cycles, info.receipt)
    }

    fn load_at(env_var: &str, rel: &str) -> Self {
        let path = std::env::var(env_var)
            .unwrap_or_else(|_| format!("{}/{rel}", env!("CARGO_MANIFEST_DIR")));
        let raw = std::fs::read(&path)
            .unwrap_or_else(|e| panic!("cannot read guest ELF at {path}: {e}"));
        let binary = risc0_binfmt::ProgramBinary::new(&raw, risc0_zkos_v1compat::V1COMPAT_ELF);
        let image_id = binary.compute_image_id().expect("image id");
        let elf = binary.encode();
        GuestProver { elf, image_id }
    }
}

// ---------------------------------------------------------------------------------------------
// Transaction building (the wallet side)
// ---------------------------------------------------------------------------------------------

struct Payment<'a> {
    to: &'a Actor,
    asset: u8,
    value: u64,
}

fn build_tx(
    pool: &Pool,
    sender: &Actor,
    pays: &[Payment],
    fee_asset: u8,
    fee_amount: u64,
    exit: Option<ExitDecl>,
) -> (ShieldedTxWitness, Vec<Vec<u8>>) {
    // How much of each asset the tx must consume.
    let mut need = [0u128; 2];
    for p in pays {
        need[p.asset as usize] += p.value as u128;
    }
    need[fee_asset as usize] += fee_amount as u128;
    if let Some(e) = &exit {
        need[e.asset as usize] += e.value as u128;
    }

    // Greedy note selection from the sender's unspent notes.
    let mut have = [0u128; 2];
    let mut spends = Vec::new();
    for (note, leaf, spent) in pool.scan(sender) {
        if spent {
            continue;
        }
        let a = note.asset as usize;
        if have[a] >= need[a] {
            continue;
        }
        have[a] += note.value as u128;
        spends.push(SpendWitness {
            note,
            sk: sender.sk,
            leaf_index: leaf,
            path: pool.path(leaf),
        });
    }
    assert!(have[0] >= need[0] && have[1] >= need[1], "{}: insufficient funds", sender.name);

    // Nullifier of the first spend seeds the consensus-assigned output rhos.
    let nf0 = nullifier(&nk_from_sk(&spends[0].sk), &spends[0].note.rho);

    // Outputs: the payments, then change per asset.
    let mut planned: Vec<(u8, u64, [u8; 32], PublicKey)> = pays
        .iter()
        .map(|p| (p.asset, p.value, p.to.pk(), p.to.enc_pk()))
        .collect();
    for a in 0..2u8 {
        let change = have[a as usize] - need[a as usize];
        if change > 0 {
            planned.push((a, change as u64, sender.pk(), sender.enc_pk()));
        }
    }

    let mut outputs = Vec::new();
    let mut ciphertexts = Vec::new();
    for (i, (asset, value, pk, enc_pk)) in planned.iter().enumerate() {
        let mut rseed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut rseed);
        let note = Note { asset: *asset, value: *value, pk: *pk, rho: output_rho(&nf0, i as u32), rseed };
        ciphertexts.push(encrypt_note(&note, enc_pk));
        outputs.push(note);
    }

    let w = ShieldedTxWitness {
        anchor: pool.root(),
        spends,
        outputs,
        ciphertexts: ciphertexts.clone(),
        fee_asset,
        fee_amount,
        exit,
    };
    (w, ciphertexts)
}

// ---------------------------------------------------------------------------------------------
// Demo scenario
// ---------------------------------------------------------------------------------------------

fn print_observer_view(tag: &str, j: &ShieldedTxJournal, cts: &[Vec<u8>], cycles: u64) {
    println!("\n  ── what the L1 observer sees ({tag}) ──");
    println!("     anchor          {}", short(&j.anchor));
    println!(
        "     nullifiers      [{}]  (random-looking; unlinkable to any note)",
        j.nullifiers.iter().map(|n| short(n)).collect::<Vec<_>>().join(", ")
    );
    println!(
        "     new commitments [{}]  (random-looking; recipients unknown)",
        j.new_cms.iter().map(|c| short(c)).collect::<Vec<_>>().join(", ")
    );
    println!(
        "     ciphertexts     {} blobs, {} bytes total (opaque)",
        cts.len(),
        cts.iter().map(|c| c.len()).sum::<usize>()
    );
    println!("     fee             {} {} → credited to the carrier poster (relayer)", fmt_amt(j.fee_amount), asset_name(j.fee_asset));
    match &j.exit {
        Some(e) => println!("     exit            {} {} to {} (public — it is a withdrawal)", fmt_amt(e.value), asset_name(e.asset), short(&e.recipient)),
        None => println!("     exit            none"),
    }
    println!("     senders/recipients/amounts of the transfer: NOT VISIBLE");
    println!("     guest cycles    {cycles}");
}

fn print_balances(pool: &Pool, actors: &[&Actor]) {
    println!("\n  ── wallet views (each key trial-decrypts the public ledger) ──");
    for a in actors {
        let b = pool.balance(a);
        println!("     {:<8} {} KAS   {} ZKAS", a.name, fmt_amt(b[0]), fmt_amt(b[1]));
    }
    println!(
        "     relayer earned: {} ZKAS + {} KAS (fees)",
        fmt_amt(pool.relayer_earned[ASSET_ZKAS as usize]),
        fmt_amt(pool.relayer_earned[ASSET_KAS as usize])
    );
}

#[tokio::main]
async fn main() {
    let with_l1 = std::env::args().any(|a| a == "--l1");
    let real = std::env::args().any(|a| a == "--real");
    if !real && std::env::var("RISC0_DEV_MODE").is_err() {
        std::env::set_var("RISC0_DEV_MODE", "1");
    }
    println!("══ ZKas Layer — shielded KAS on Kaspa, demo ══");
    println!(
        "   proving mode: {}",
        if real { "REAL STARK (this takes a while)" } else { "dev (real guest execution, fake seal — pass --real for a STARK)" }
    );

    let prover = GuestProver::load();
    println!("   spend guest image id: {}", prover.image_id);

    let alice = Actor::new("Alice");
    let bob = Actor::new("Bob");
    let charlie = Actor::new("Charlie");
    let actors = [&alice, &bob, &charlie];
    let mut pool = Pool::new();
    let mut receipts: Vec<risc0_zkvm::Receipt> = Vec::new();

    // ── 1. Edges: deposits (amount public, recipient hidden from block one) ──
    println!("\n■ step 1 — deposits (the transparent edge)");
    for (who, asset, amount, tag) in [
        (&alice, ASSET_KAS, 100 * UNIT, "Alice deposits 100 KAS into the covenant"),
        (&alice, ASSET_ZKAS, 50 * UNIT, "Alice migrates 50 ZKAS in (burn-and-mint)"),
        (&charlie, ASSET_KAS, 20 * UNIT, "Charlie deposits 20 KAS into the covenant"),
    ] {
        let mut fake_txid = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut fake_txid);
        let mut rseed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut rseed);
        let note = Note { asset, value: amount, pk: who.pk(), rho: deposit_rho(&fake_txid, 0), rseed };
        let ct = encrypt_note(&note, &who.enc_pk());
        pool.batch_deposits.push(note_cm(&note));
        let leaf = pool.add_leaf(note_cm(&note), ct);
        println!("   {tag}: L1 sees amount {} {} → commitment {} (leaf {leaf}); the owner is hidden", fmt_amt(amount), asset_name(asset), short(&note_cm(&note)));
    }
    print_balances(&pool, &actors);

    // ── 2. Alice → Bob, private, ZKAS fee ──
    println!("\n■ step 2 — Alice pays Bob 30 KAS privately (fee: {} ZKAS)", fmt_amt(MIN_FEE_ZKAS));
    let (w, cts) = build_tx(
        &pool,
        &alice,
        &[Payment { to: &bob, asset: ASSET_KAS, value: 30 * UNIT }],
        ASSET_ZKAS,
        MIN_FEE_ZKAS,
        None,
    );
    let (j, cycles, r) = prover.prove(&w);
    receipts.push(r);
    pool.apply(&j, cts.clone());
    print_observer_view("Alice→Bob", &j, &cts, cycles);
    let bob_found = pool.scan(&bob);
    println!("  ── what BOB sees (his key trial-decrypts) ──");
    for (n, leaf, _) in &bob_found {
        println!("     received {} {} at leaf {leaf}", fmt_amt(n.value), asset_name(n.asset));
    }
    print_balances(&pool, &actors);

    // ── 3. Charlie → Alice, private, KAS fee at the premium ──
    let kas_fee = MIN_FEE_ZKAS * KAS_FEE_PREMIUM;
    println!("\n■ step 3 — Charlie has NO ZKAS: he pays Alice 5 KAS, fee in KAS at {KAS_FEE_PREMIUM}x ({} KAS)", fmt_amt(kas_fee));
    let (w, cts) = build_tx(
        &pool,
        &charlie,
        &[Payment { to: &alice, asset: ASSET_KAS, value: 5 * UNIT }],
        ASSET_KAS,
        kas_fee,
        None,
    );
    let (j, cycles, r) = prover.prove(&w);
    receipts.push(r);
    pool.apply(&j, cts.clone());
    print_observer_view("Charlie→Alice", &j, &cts, cycles);
    print_balances(&pool, &actors);

    // ── 4. Bob exits 10 KAS to L1 ──
    println!("\n■ step 4 — Bob withdraws 10 KAS to a fresh L1 address (exits are public by definition)");
    let mut l1_addr = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut l1_addr);
    let (w, cts) = build_tx(
        &pool,
        &bob,
        &[],
        ASSET_KAS,
        kas_fee,
        Some(ExitDecl { asset: ASSET_KAS, value: 10 * UNIT, recipient: l1_addr }),
    );
    let (j, cycles, r) = prover.prove(&w);
    receipts.push(r);
    pool.apply(&j, cts.clone());
    print_observer_view("Bob exit", &j, &cts, cycles);
    println!("     → settlement: the covenant's next advance carves a permission output of {} KAS to {}", fmt_amt(10 * UNIT), short(&l1_addr));
    print_balances(&pool, &actors);

    // ── 5. Soundness spot-checks ──
    println!("\n■ step 5 — soundness spot-checks (each must FAIL)");
    // 5a. Double spend: replay Bob's exit journal.
    let replay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut p2 = Pool::new();
        p2.leaves = pool.leaves.clone();
        p2.roots = pool.roots.clone();
        p2.nullifiers = pool.nullifiers.clone();
        p2.apply(&j, cts.clone());
    }));
    println!("   replaying a spent journal: {}", if replay.is_err() { "REJECTED (double spend)" } else { "ACCEPTED ?!" });
    // 5b. Inflation: try to prove a tx that creates value.
    let (mut wbad, _) = build_tx(
        &pool,
        &alice,
        &[Payment { to: &bob, asset: ASSET_KAS, value: 1 * UNIT }],
        ASSET_ZKAS,
        MIN_FEE_ZKAS,
        None,
    );
    wbad.outputs[0].value += 1;
    let infl = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(&wbad)));
    println!("   proving an inflating tx:    {}", if infl.is_err() { "REJECTED (per-asset balance violated in-guest)" } else { "ACCEPTED ?!" });
    // 5c. Theft: spend Alice's note with Bob's key.
    let (mut wtheft, _) = build_tx(
        &pool,
        &alice,
        &[Payment { to: &bob, asset: ASSET_KAS, value: 1 * UNIT }],
        ASSET_ZKAS,
        MIN_FEE_ZKAS,
        None,
    );
    for s in &mut wtheft.spends {
        s.sk = bob.sk;
    }
    let theft = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prover.prove(&wtheft)));
    println!("   spending with a wrong key:  {}", if theft.is_err() { "REJECTED (spend authority checked in-guest)" } else { "ACCEPTED ?!" });

    println!("\n══ pool done — {} leaves, {} nullifiers, exits queued: {} ══", pool.leaves.len(), pool.nullifiers.len(), pool.exits.len());

    // ── 5b. THE AGGREGATE PROOF: one recursion proof vouching for the whole batch ──
    println!("\n■ batch aggregation — recursively verify {} spend receipts + prove the state transition", receipts.len());
    let batch_prover = GuestProver::load_at(
        "SHIELDED_BATCH_ELF",
        "../../zk/backend/risc0/shielded-batch/compiled/program.elf",
    );
    println!("   batch guest image id: {}", batch_prover.image_id);
    let batch_witness = BatchWitness {
        inner_image_id: prover.image_id.into(),
        prev_frontier: Frontier::default(),
        prev_nf_root: nf_default_ladder()[NF_DEPTH],
        deposits: pool.batch_deposits.clone(),
        txs: pool.batch_txs.clone(),
    };
    // Host-side dry run first: the guest runs the identical function.
    let expected = verify_batch(&batch_witness).expect("host batch check");
    assert_eq!(
        expected.new_state,
        batch_state(&pool.frontier.root(), &pool.nf_acc.root()),
        "host state must equal the batch's proven successor"
    );
    let mut env = ExecutorEnv::builder();
    env.write(&batch_witness).expect("ser");
    for r in &receipts {
        env.add_assumption(r.clone());
    }
    let env = env.build().expect("env");
    let info = default_prover().prove(env, &batch_prover.elf).expect("batch proving failed");
    info.receipt.verify(batch_prover.image_id).expect("batch receipt must verify");
    let bj: vprogs_shielded_demo_types::BatchJournal =
        info.receipt.journal.decode().expect("batch journal");
    assert_eq!(bj, expected, "guest and host must derive the identical batch journal");
    println!(
        "   ✔ ONE proof covers {} deposits + {} private txs: state {} → {} ({} cycles)",
        pool.batch_deposits.len(),
        bj.tx_count,
        short(&bj.prev_state),
        short(&bj.new_state),
        info.stats.total_cycles
    );
    println!(
        "   journal exposes only: state roots, {} exit(s), fees [{} KAS, {} ZKAS], inner image id",
        bj.exits.len(),
        fmt_amt(bj.fees[0]),
        fmt_amt(bj.fees[1])
    );

    // ── 6. The custody leg: make Bob's exit REAL on a live Kaspa simnet ──
    // The covenant commits the BATCH-PROVEN state, and the exit comes from the batch journal —
    // the L1 side settles exactly what the aggregate proof vouched for.
    if with_l1 {
        let e = bj.exits[0];
        l1::run_custody_leg(bj.new_state, e.recipient, e.value).await;
    } else {
        println!("   (pass --l1 to run the custody leg on a real kaspad simnet: covenant, deposits, settlement, sweep)");
    }
}
