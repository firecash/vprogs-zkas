# Deploying the ZKas L2 settler

`tn10-flow` is the long-running settler/relayer: it follows the L1 chain over wRPC, tracks the
covenant's settled state (reorg-aware), and — in proving mode — proves each bundle and lands the
settlement transaction on L1. This directory packages it as a systemd service.

## Prerequisites

- An L1 node (a `zkas-rusty` node) reachable over **wRPC Borsh**. Start it with `--rpclisten-borsh`
  (ZKas mainnet default Borsh port is `17810`); the gRPC listener alone is not enough.
- A funded secp256k1 key for the covenant/carrier transactions (`TN10_PRIVATE_KEY`).
- The `tn10-flow` binary. Build it from the workspace root:
  ```
  cargo build --release --bin tn10-flow
  cp target/release/tn10-flow /root/zkas/bin/tn10-flow
  ```

## Install

```
mkdir -p /etc/zkas-settler /var/lib/zkas-settler
cp settler.env.example /etc/zkas-settler/settler.env
chmod 600 /etc/zkas-settler/settler.env      # holds the private key
# edit /etc/zkas-settler/settler.env: set TN10_WRPC_URL and TN10_PRIVATE_KEY

cp zkas-settler.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now zkas-settler.service
journalctl -u zkas-settler -f
```

On first run with no `TN10_COVENANT_ID`, the service bootstraps a fresh covenant; the id is logged
and persisted under `TN10_DATA_DIR`. Set `TN10_COVENANT_ID` + `TN10_START_FROM` to attach to an
existing covenant instead.

## Modes

- **`TN10_SETTLE=0`** (default): execution-only. Tracks state, reorgs, and settlements without
  proving. Safe to run anywhere; this is how you observe the L2 without a prover.
- **`TN10_SETTLE=1`**: proving + settlement. Drives the full prover stack and lands settlements on
  L1. Secure (non-dev-mode) proofs require a **CUDA build** and `RISC0_DEV_MODE` unset — see the
  `cuda` feature. Without a GPU you can run this with `RISC0_DEV_MODE=1` for dev-mode proofs, which
  are NOT valid on-chain (the `OpZkPrecompile` covenant check rejects them) and are for testing the
  pipeline only.
