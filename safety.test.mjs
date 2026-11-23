import test from "node:test";
import assert from "node:assert/strict";
import { DEMO_CASES, inspectUrl, analyzeSafety, redactSensitiveText } from "./safety.mjs";

test("inspectUrl catches brand impersonation, typosquatting and punycode", () => {
  const imp = inspectUrl("https://metamask-verify-secure.xyz/login");
  assert.ok(imp.risk >= 50);
  assert.ok(imp.findings.some(f => f.includes("metamask")));

  const typo = inspectUrl("https://paypa1.com/auth");
  assert.ok(typo.risk >= 30);
  assert.ok(typo.findings.some(f => f.includes("Typosquatting")));

  const safe = inspectUrl("https://github.com/tungdeptrai07/safespace-guard");
  assert.equal(safe.risk, 0);
});

test("analyzeSafety flags phishing DM and doxxing threats as Critical", () => {
  const phish = analyzeSafety(DEMO_CASES.phishing_wallet.text);
  assert.equal(phish.severity, "Critical");
  assert.ok(phish.score >= 65);
  assert.ok(phish.categories.includes("Phishing / Malicious Link"));

  const dox = analyzeSafety(DEMO_CASES.doxxing_harassment.text);
  assert.equal(dox.severity, "Critical");
  assert.ok(dox.categories.includes("Harassment / Safety Threat"));
});

test("analyzeSafety keeps benign message Safe", () => {
  const safe = analyzeSafety(DEMO_CASES.safe_message.text);
  assert.equal(safe.severity, "Safe");
  assert.equal(safe.score, 0);
});

test("redactSensitiveText masks emails, phones, SSNs and 64-hex private keys", () => {
  const out = redactSensitiveText("Email a@b.com, phone 415-555-0192, ssn 123-45-6789, key 0x" + "a".repeat(64));
  assert.match(out, /\[REDACTED_EMAIL\]/);
  assert.match(out, /\[REDACTED_PHONE\]/);
  assert.match(out, /\[REDACTED_ID\]/);
  assert.match(out, /\[REDACTED_PRIVATE_KEY\]/);
});
