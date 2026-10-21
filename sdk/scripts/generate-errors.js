#!/usr/bin/env node
// Reads contracts/payment-processing-contract/src/error.rs and regenerates:
//   sdk/error-registry.json
//   sdk/errors.ts

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "../..");
const ERROR_RS = path.join(ROOT, "contracts/payment-processing-contract/src/error.rs");
const OUT_JSON = path.join(ROOT, "sdk/error-registry.json");
const OUT_TS   = path.join(ROOT, "sdk/errors.ts");

// Human-readable messages keyed by variant name (extend as needed)
const MESSAGES = {
  Unauthorized:               "Caller lacks permission to perform this action",
  AdminAlreadySet:            "Admin has already been initialised",
  MerchantNotFound:           "Merchant is not registered",
  MerchantAlreadyRegistered:  "A merchant with this address is already registered",
  MerchantInactive:           "Merchant account is deactivated",
  MerchantAlreadyActive:      "Merchant is already active and cannot be reactivated",
  PaymentNotFound:            "Order ID not found",
  PaymentAlreadyExists:       "A payment with this order ID already exists",
  InvalidAmount:              "Amount must be greater than zero",
  InvalidSignature:           "Signature verification failed",
  PaymentExpired:             "Order is past its expiry timestamp",
  InsufficientBalance:        "Payer or merchant does not have enough token balance to complete the transfer",
  RefundNotFound:             "Refund ID not found",
  RefundAlreadyExists:        "A refund with this ID already exists",
  RefundWindowExpired:        "The 30-day refund window has passed",
  RefundAmountExceedsPayment: "Cumulative refund amount exceeds the original payment",
  RefundNotApproved:          "Refund is not in Approved state",
  RefundAlreadyCompleted:     "Refund has already been completed or rejected",
  RefundNotRejected:          "Refund must be in Rejected state to be disputed",
  DisputeUnauthorized:        "Dispute can only be raised by the original payer",
  RefundNotDisputed:          "Refund is not in Disputed state; cannot resolve",
  MultisigNotFound:           "Multisig payment not found",
  MultisigAlreadySigned:      "This signer has already signed the multisig payment",
  MultisigAlreadyExecuted:    "Multisig payment has already been executed",
  InsufficientSignatures:     "Not all required signers have signed",
  InvalidInput:               "General input validation failure",
  // StorageError (51) removed — variant was never returned (SC-009).
  ArithmeticError:            "Arithmetic overflow or underflow",
  SubscriptionNotFound:       "Subscription ID not found in storage",
  SubscriptionAlreadyExists:  "A subscription with this ID already exists",
  SubscriptionNotActive:      "Subscription is not in Active state (e.g. already cancelled)",
  SubscriptionIntervalNotElapsed: "Payment interval has not elapsed since the last charge",
  TokenNotAllowed:            "The token contract address is not on the admin-managed allowlist",
};

const src = fs.readFileSync(ERROR_RS, "utf8");
const variantRe = /^\s{4}(\w+)\s*=\s*(\d+),/gm;

const errors = [];
let m;
while ((m = variantRe.exec(src)) !== null) {
  const name = m[1];
  const code = parseInt(m[2], 10);
  errors.push({ code, name, message: MESSAGES[name] ?? `Error code ${code}` });
}
errors.sort((a, b) => a.code - b.code);

// --- JSON ---
const registry = { version: "1.0.0", source: "contracts/payment-processing-contract/src/error.rs", errors };
fs.writeFileSync(OUT_JSON, JSON.stringify(registry, null, 2) + "\n");

// --- TypeScript ---
const maxNameLen = Math.max(...errors.map(e => e.name.length));
const enumLines = errors.map(e => `  ${e.name.padEnd(maxNameLen)} = ${e.code},`).join("\n");
const mapLines  = errors.map(e => `  ${e.code}: "${e.message}",`).join("\n");

const ts = `// AUTO-GENERATED — do not edit by hand.
// Run \`node sdk/scripts/generate-errors.js\` to regenerate from error-registry.json.

export enum PulsarErrorCode {
${enumLines}
}

const registry: Record<number, string> = {
${mapLines}
};

/** Map a numeric contract error code to a human-readable message. */
export function getErrorMessage(code: number): string {
  return registry[code] ?? \`Unknown contract error (code \${code})\`;
}
`;
fs.writeFileSync(OUT_TS, ts);

console.log(`Generated ${errors.length} error entries.`);
console.log(`  -> ${OUT_JSON}`);
console.log(`  -> ${OUT_TS}`);
