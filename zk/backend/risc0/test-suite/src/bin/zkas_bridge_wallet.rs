//! `zkas-bridge-wallet`: peg-in (deposit) and peg-out (withdraw) for the ZKas L2 rollup bridge.
//!
//! `deposit` funds the covenant on L1 and credits an L2 user; `withdraw` moves an L2 balance back to
//! an L1 destination. Each builds the runtime carrier transaction with the same (tested)
//! `runtime_flow` builders the settlement e2e uses, funds it from `--fund-scalar`'s L1 UTXOs, and
//! submits it over gRPC. `--dry-run` prints the unfunded carrier instead of submitting.
//!
//! The carrier builders live in the test-suite for now; productionizing them into an `l1` crate is a
//! follow-up so this CLI need not depend on the test-suite.

use clap::{Parser, Subcommand};
use kaspa_addresses::Prefix;
use kaspa_consensus_core::{
    config::params::{DEVNET_PARAMS, MAINNET_PARAMS, Params, SIMNET_PARAMS, TESTNET_PARAMS},
    constants::TX_VERSION_TOCCATA,
    subnets::SUBNETWORK_ID_NATIVE,
};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};
use vprogs_l1_wallet::Wallet;
use vprogs_zk_backend_risc0_test_suite::runtime_flow::{RuntimeCarrier, RuntimeSigner, deposit_carrier, withdraw_carrier};

/// Peg-in/peg-out wallet for the ZKas L2 bridge.
#[derive(Parser)]
#[command(name = "zkas-bridge-wallet")]
struct Cli {
    /// gRPC address of an L1 node.
    #[arg(long, default_value = "127.0.0.1:16110")]
    node: String,
    /// L1 network (selects consensus params and the address HRP; must match the node). The rollup
    /// L1 is transparent, so use testnet/simnet (shielded mainnet has no spendable UTXOs).
    #[arg(long, default_value = "testnet")]
    network: String,
    /// Secret scalar of the L1 key that funds and pays for the carrier transaction.
    #[arg(long)]
    fund_scalar: u64,
    /// Build and print the unfunded carrier instead of funding and submitting it.
    #[arg(long)]
    dry_run: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

/// The two bridge directions.
#[derive(Subcommand)]
enum Cmd {
    /// Print the fund key's L1 address (mine or send coins here to fund deposits).
    Address,
    /// Peg in: fund the covenant on L1 and credit an L2 user.
    Deposit {
        /// Covenant id, 64 hex chars.
        #[arg(long)]
        covenant: String,
        /// Secret scalar of the L2 user to credit.
        #[arg(long)]
        user_scalar: u64,
        /// Amount to deposit, in sompi.
        #[arg(long)]
        value: u64,
    },
    /// Peg out: move an L2 balance to an L1 destination public key.
    Withdraw {
        /// Secret scalar of the L2 user withdrawing.
        #[arg(long)]
        user_scalar: u64,
        /// Amount to withdraw, in sompi.
        #[arg(long)]
        amount: u64,
        /// Destination L1 x-only public key, 64 hex chars.
        #[arg(long)]
        dest: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // The address command needs neither a node nor the carrier machinery.
    if let Cmd::Address = cli.cmd {
        let prefix = Prefix::from(params_for(&cli.network).net.network_type());
        println!("{}", RuntimeSigner::from_scalar(cli.fund_scalar).p2pk_address(prefix));
        return;
    }

    // Build the runtime carrier for the requested direction.
    let carrier = match &cli.cmd {
        Cmd::Address => unreachable!("handled above"),
        Cmd::Deposit { covenant, user_scalar, value } => {
            let user = RuntimeSigner::from_scalar(*user_scalar);
            deposit_carrier(hash32(covenant), &user, *value)
        }
        Cmd::Withdraw { user_scalar, amount, dest } => {
            let user = RuntimeSigner::from_scalar(*user_scalar);
            withdraw_carrier(&user, *amount, &hash32(dest))
        }
    };

    // Dry run: show the unfunded carrier and stop before touching a node or a key.
    if cli.dry_run {
        let tx = carrier.into_unfunded();
        println!("carrier payload : {}", hex(&tx.payload));
        println!("extra outputs   : {}", tx.outputs.len());
        return;
    }

    // Fund from the L1 key's UTXOs, then submit.
    let fund = RuntimeSigner::from_scalar(cli.fund_scalar);
    let client = connect(&cli.node).await;
    let wallet = Wallet::new(&client, params_for(&cli.network), fund.secp_keypair());
    let tx = build_funded(&wallet, &carrier).await;
    match wallet.submit_transaction(&tx).await {
        Ok(id) => println!("submitted {id}"),
        Err(e) => fatal(&format!("submit failed: {e}")),
    }
}

/// Funds and signs `carrier`: the carrier's extra outputs (e.g. a deposit funding output) ride along,
/// and its `payload` closure finalizes the action's signatures over the funded transaction.
async fn build_funded<C: RpcApi + ?Sized>(
    wallet: &Wallet<'_, C>,
    carrier: &RuntimeCarrier,
) -> kaspa_consensus_core::tx::Transaction {
    wallet
        .build_signed_carrier(carrier.extra_outputs().to_vec(), SUBNETWORK_ID_NATIVE, TX_VERSION_TOCCATA, |rest| carrier.payload(rest))
        .await
}

/// Selects consensus params (and hence the address HRP) for a network name.
fn params_for(network: &str) -> &'static Params {
    match network {
        "mainnet" => &MAINNET_PARAMS,
        "testnet" => &TESTNET_PARAMS,
        "simnet" => &SIMNET_PARAMS,
        "devnet" => &DEVNET_PARAMS,
        other => fatal(&format!("unknown network '{other}' (mainnet|testnet|simnet|devnet)")),
    }
}

/// Connects a direct-mode gRPC client to `address`.
async fn connect(address: &str) -> GrpcClient {
    GrpcClient::connect_with_args(NotificationMode::Direct, format!("grpc://{address}"), None, true, None, false, Some(500_000), Default::default())
        .await
        .unwrap_or_else(|e| fatal(&format!("connect {address}: {e}")))
}

/// Decodes a 32-byte hex value, aborting on malformed input.
fn hash32(s: &str) -> [u8; 32] {
    let s = s.trim();
    if s.len() != 64 {
        fatal("expected a 64-hex-char (32-byte) value");
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or_else(|_| fatal("bad hex"));
    }
    out
}

/// Lowercase hex of a byte slice.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Prints `msg` to stderr and exits non-zero.
fn fatal(msg: &str) -> ! {
    eprintln!("zkas-bridge-wallet: {msg}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two carriers the CLI builds are well-formed: a deposit contributes exactly one funding
    /// output carrying the deposited value (paid to the covenant deposit script) and a
    /// signature-free payload; a withdraw contributes no extra output and a signed payload.
    #[test]
    fn cli_carriers_are_well_formed() {
        let user = RuntimeSigner::from_scalar(7);

        let dep = deposit_carrier([0x11; 32], &user, 4_242).into_unfunded();
        assert_eq!(dep.outputs.len(), 1, "deposit funds exactly one covenant output");
        assert_eq!(dep.outputs[0].value, 4_242, "funding output carries the deposit value");
        assert!(!dep.payload.is_empty(), "deposit carries an action payload");

        let wd = withdraw_carrier(&user, 100, &[0x22; 32]).into_unfunded();
        assert_eq!(wd.outputs.len(), 0, "withdraw contributes no L1 funding output");
        assert!(!wd.payload.is_empty(), "withdraw carries a signed action payload");
    }
}
