# Stellar Mainnet Deployment Guide (MISC-015)

This guide covers deploying `payment-processing-contract` to the Stellar
**public network (mainnet / pubnet)**. The main [README](../README.md)
documents local and testnet deployment only; mainnet carries real-value risk
(misconfigured admin keys, a missed initialisation step, or an unaudited
network setting can lock or drain funds), so it gets its own checklist.

Read this guide fully before running any command against `--network public`.
None of the steps here are reversible once funds start moving through the
contract.

## Pre-deployment security checklist

Work through this list before touching mainnet. Do not skip items because
"it worked on testnet."

- [ ] **Security audit / review completed.** See
      [`docs/security-audit.md`](security-audit.md) for the project's audit
      status; do not deploy unaudited changes straight to mainnet.
- [ ] **CI is green on the exact commit being deployed**, including the WASM
      size gate (`cargo build --release` artifact under 100 KB — see
      [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)) and
      `cargo audit` / `cargo deny`.
- [ ] **Admin key(s) generated on hardware the deploying operator controls**,
      never reused from testnet or from any other project. See
      [Key generation](#1-key-generation) below.
- [ ] **Admin multi-sig threshold decided in advance.** `set_admin` takes a
      list of admin addresses and a `threshold`; decide how many of how many
      signers are required for admin actions (`set_whitelist_mode`,
      `set_token_allowlist_mode`, `set_merchant_tier`, pause/unpause, etc.)
      *before* calling it — it can only be called once per contract instance
      (`PaymentError::AdminAlreadySet` thereafter).
- [ ] **Secret keys stored in a secrets manager or hardware wallet**, not in
      shell history, `.env` files committed to git, or CI logs. If you must
      use a CI secret (as `deploy-testnet` does for testnet, via
      `TESTNET_SECRET_KEY`), scope it to a dedicated mainnet deployment key
      with no other privileges and rotate it after use if possible.
- [ ] **Funding account amount sized for real base reserves**, not the
      Friendbot-funded 10,000 XLM used on testnet — see
      [Account funding](#2-account-funding).
- [ ] **Token allowlist / merchant whitelist mode decided.** Decide, before
      going live, whether `set_token_allowlist_mode` and
      `set_whitelist_mode` should be enabled on mainnet (recommended for a
      production deployment — see the inline docs on those functions in
      `src/lib.rs`), and prepare the `add_allowed_token` /
      `approve_merchant_registration` calls you'll need right after
      `set_admin`.
- [ ] **Rollback / pause plan.** Confirm who holds the keys needed to call
      the contract's pause functionality and under what conditions it would
      be used, before an incident — not during one.
- [ ] **Contract ID and WASM hash recorded somewhere outside your terminal**
      (e.g. a runbook, a password manager note, or the release's
      `payment_processing_contract.wasm.sha256` artifact produced by the
      `release` CI job) immediately after deployment, per
      [Step 5](#5-verify).

## Step-by-step deployment

### 1. Key generation

Generate a dedicated mainnet deployer key. Do not reuse a testnet key.

```bash
stellar keys generate --global mainnet-deployer --network public
stellar keys address mainnet-deployer   # public key (G...) — safe to share
stellar keys show mainnet-deployer      # secret key (S...) — NEVER share or commit this
```

Treat the secret key as you would a production database password: store it
in a secrets manager (1Password, Vault, AWS Secrets Manager, etc.) or on a
hardware signer, not in a plaintext file.

Separately, generate (or designate) the address(es) that will become the
contract's admin(s) via `set_admin`. These may be the same key as the
deployer or, for a multi-sig setup, a distinct set of addresses held by
different people/devices.

### 2. Account funding

Unlike testnet, there is no Friendbot on mainnet. Fund the deployer account
with real XLM from an exchange, an existing wallet, or a liquidity provider.

At minimum, the account needs:
- The [base reserve](https://developers.stellar.org/docs/learn/fundamentals/lumens#base-reserves)
  for the account itself (currently 1 XLM per reserve unit — check current
  network parameters, as these can change).
- Enough XLM to cover the resource fees for the contract deployment and
  initial admin/configuration transactions (deployment of a ~90 KB WASM
  payload is more expensive than invoking an already-deployed contract;
  budget several XLM to be safe, and check current fees via
  `stellar network` tooling or Stellar Laboratory before sending funds).

Verify the funded balance before continuing:

```bash
stellar keys address mainnet-deployer
# then check the balance for that address with your preferred
# Horizon/RPC query or a block explorer (e.g. stellar.expert)
```

### 3. WASM upload / contract deployment

Build the release WASM exactly as CI does, so the deployed bytecode matches
what was audited and size-checked:

```bash
cargo build --target wasm32-unknown-unknown --release --locked
```

(Optional but recommended) verify this matches a CI-built artifact — compare
against the `payment_processing_contract.wasm.sha256` checksum published by
the `release` job in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml)
for the tag you are deploying, or follow
[`docs/reproducible-builds.md`](reproducible-builds.md) to rebuild
byte-for-byte and compare hashes yourself.

Deploy to the public network:

```bash
stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/payment_processing_contract.wasm \
  --source-account mainnet-deployer \
  --network public
```

This prints a contract address starting with `C`. Save it immediately:

```bash
export CONTRACT_ID="<address printed above>"
```

### 4. Initialise

The contract has no owner until `set_admin` is called — do this
**immediately** after deployment, before any other party could race you to
it (anyone can call `set_admin` on an un-initialised contract instance, and
it can only be called once).

```bash
stellar contract invoke \
  --id "$CONTRACT_ID" \
  --source-account mainnet-deployer \
  --network public \
  -- set_admin \
  --admins '["<ADMIN_ADDRESS_1>","<ADMIN_ADDRESS_2>"]' \
  --threshold 2
```

Adjust `--admins` / `--threshold` to match the multi-sig policy you decided
on in the [pre-deployment checklist](#pre-deployment-security-checklist). A
single-admin deployment is `--admins '["<ADMIN_ADDRESS>"]' --threshold 1`,
but a production deployment handling real funds should use more than one
independent signer.

Immediately follow up with whatever allowlist/whitelist configuration you
decided on, for example:

```bash
stellar contract invoke --id "$CONTRACT_ID" --source-account mainnet-deployer \
  --network public -- set_token_allowlist_mode \
  --admins '["<ADMIN_ADDRESS_1>","<ADMIN_ADDRESS_2>"]' --enabled true

stellar contract invoke --id "$CONTRACT_ID" --source-account mainnet-deployer \
  --network public -- add_allowed_token \
  --admins '["<ADMIN_ADDRESS_1>","<ADMIN_ADDRESS_2>"]' --token "<TOKEN_CONTRACT_ADDRESS>"
```

### 5. Verify

After initialisation, confirm the contract is in the expected state before
announcing it or routing any real payment traffic to it:

```bash
# Confirm the version/admin state is as expected
stellar contract invoke --id "$CONTRACT_ID" --source-account mainnet-deployer \
  --network public -- get_version

# Confirm the token allowlist state, if you enabled it
stellar contract invoke --id "$CONTRACT_ID" --source-account mainnet-deployer \
  --network public -- is_token_allowed --token "<TOKEN_CONTRACT_ADDRESS>"
```

Record, outside your terminal history:
- The contract ID (`$CONTRACT_ID`).
- The exact git commit/tag deployed and its WASM SHA-256 (from the `release`
  CI job, or computed locally with `sha256sum`).
- The admin address(es) and threshold configured.
- The date/time and operator who performed the deployment.

Only after this verification step should the mainnet contract ID be shared
with downstream integrators or put in front of real payment volume.

## See also

- [`README.md`](../README.md) — local/testnet setup, environment seeding,
  general contract usage.
- [`docs/reproducible-builds.md`](reproducible-builds.md) — rebuilding the
  WASM byte-for-byte to verify what was deployed.
- [`docs/security-audit.md`](security-audit.md) — audit status and scope.
- [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) — the
  `deploy-testnet` job this guide's mainnet flow mirrors (testnet deploys
  are automated in CI; mainnet deploys are intentionally manual and
  checklist-gated).
