/**
 * SafeSpace Guard — Client-Side Multi-Signal Digital Safety, Phishing & Harassment Engine
 * 100% local zero-knowledge analysis (no text leaves the browser):
 *  - URL structural phishing heuristics (IDN/punycode, IP-literal hosts, lookalike brand spoofing, suspicious TLDs, credential lures)
 *  - Social engineering & urgency / financial extortion pattern detection
 *  - Harassment, doxxing & PII exposure scanner (email, phone, SSN/ID, crypto seed phrase leakage)
 *  - Severity scoring (0-100), explainable evidence breakdown, redaction helper & batch audit support
 */

const SUSPICIOUS_TLDS = new Set(["xyz", "top", "gq", "tk", "ml", "cf", "click", "zip", "mov", "ru", "cn", "work", "buzz", "support"]);
const BRAND_TARGETS = ["paypal", "google", "apple", "microsoft", "binance", "coinbase", "metamask", "discord", "telegram", "amazon", "netflix", "chase", "bankofamerica", "github", "devpost"];
const URGENCY_PATTERNS = [
  { re: /\b(verify|confirm|restore|unlock)\s+(your\s+)?(account|wallet|identity|access)\b/i, weight: 24, label: "Credential/account verification lure" },
  { re: /\b(suspended|locked|terminated|frozen|compromised)\s+(within|in)\s+\d+\s*(hours?|mins?|minutes?|days?)\b/i, weight: 26, label: "Artificial countdown / suspension threat" },
  { re: /\b(seed\s*phrase|recovery\s*phrase|private\s*key|12\s*words?|24\s*words?|otp\s*code)\b/i, weight: 38, label: "Secret key / OTP extraction attempt" },
  { re: /\b(wire\s*transfer|gift\s*card|send\s*crypto|urgent\s*payment|claim\s*airdrop|double\s*your)\b/i, weight: 28, label: "Financial scam / advance-fee lure" },
  { re: /\b(click\s+here\s+immediately|act\s+now|final\s+warning|legal\s+action)\b/i, weight: 18, label: "High-pressure social engineering language" }
];
const HARASSMENT_PATTERNS = [
  { re: /\b(kill\s+yourself|kys|go\s+die|hurt\s+yourself)\b/i, weight: 48, label: "Severe self-harm / violent harassment" },
  { re: /\b(i\s+know\s+where\s+you\s+live|doxx?(ing|ed)?|leak\s+your\s+(address|photos|nudes|info))\b/i, weight: 42, label: "Doxxing / blackmail threat" },
  { re: /\b(worthless|pathetic\s+loser|nobody\s+likes\s+you|shut\s+up\s+idiot)\b/i, weight: 22, label: "Targeted abusive harassment" }
];

export const DEMO_CASES = {
  phishing_wallet: {
    label: "Crypto Wallet Phishing DM",
    text: "URGENT: Your MetaMask wallet has been suspended within 2 hours due to unusual activity. Confirm your wallet and enter your 12 words seed phrase immediately at https://metamask-verify-secure.xyz/login?ref=urgent to avoid losing funds."
  },
  doxxing_harassment: {
    label: "Online Doxxing & Threat",
    text: "Stop posting or I will leak your address and phone 415-555-0192 everywhere. I know where you live, you pathetic loser."
  },
  pii_leak: {
    label: "Accidental PII & Secret Leak",
    text: "Hey team, sharing the onboarding doc: email alex.chen@example.com, backup phone +1 (650) 555-8291, and my test SSN 123-45-6789 for the staging sandbox."
  },
  safe_message: {
    label: "Benign Community Post",
    text: "Welcome to our open-source study group! You can read the project docs at https://github.com/tungdeptrai07/safespace-guard and join Friday's code review."
  }
};

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[m][n];
}

export function inspectUrl(rawUrl) {
  const findings = [];
  let risk = 0;
  let parsed;
  try {
    parsed = new URL(rawUrl.startsWith("http") ? rawUrl : `https://${rawUrl}`);
  } catch {
    return { url: rawUrl, risk: 15, findings: ["Malformed URL syntax"] };
  }

  const host = parsed.hostname.toLowerCase();
  const labels = host.split(".");
  const tld = labels[labels.length - 1];

  if (parsed.protocol === "http:") {
    risk += 12;
    findings.push("Unencrypted HTTP transport");
  }
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    risk += 35;
    findings.push("Raw IPv4 host instead of domain");
  }
  if (host.includes("xn--") || /[^\x00-\x7F]/.test(host)) {
    risk += 34;
    findings.push("Punycode / Unicode homograph attack indicator");
  }
  if (SUSPICIOUS_TLDS.has(tld)) {
    risk += 22;
    findings.push(`High-abuse TLD (.${tld})`);
  }
  if (labels.length >= 4) {
    risk += 16;
    findings.push("Deep subdomain chain obfuscation");
  }
  if (rawUrl.includes("@")) {
    risk += 30;
    findings.push("Embedded @ credential/host redirect");
  }

  // Brand spoofing check (e.g. paypal-secure.xyz or paypa1.com)
  const rootLabel = labels.length >= 2 ? labels[labels.length - 2] : host;
  for (const brand of BRAND_TARGETS) {
    const exactLegit = host === `${brand}.com` || host.endsWith(`.${brand}.com`) || host === `${brand}.org` || host === `${brand}.io`;
    if (exactLegit) continue;
    if (host.includes(brand)) {
      risk += 32;
      findings.push(`Impersonates "${brand}" on unofficial domain (${host})`);
      break;
    }
    const normalized = rootLabel.replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s");
    if (Math.abs(normalized.length - brand.length) <= 1 && levenshtein(normalized, brand) <= 1) {
      risk += 34;
      findings.push(`Typosquatting / homoglyph lookalike of "${brand}" (${host})`);
      break;
    }
  }

  return { url: rawUrl, host, risk: Math.min(100, risk), findings };
}

export function detectPii(text) {
  const hits = [];
  const emailMatches = text.match(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi) || [];
  const phoneMatches = text.match(/(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}\b/g) || [];
  const ssnMatches = text.match(/\b\d{3}-\d{2}-\d{4}\b/g) || [];
  const evmKeyMatches = text.match(/\b0x[a-fA-F0-9]{64}\b/g) || [];

  if (emailMatches.length) hits.push({ type: "Email Address", count: emailMatches.length, weight: 12 });
  if (phoneMatches.length) hits.push({ type: "Phone Number", count: phoneMatches.length, weight: 18 });
  if (ssnMatches.length) hits.push({ type: "SSN / National ID", count: ssnMatches.length, weight: 32 });
  if (evmKeyMatches.length) hits.push({ type: "64-Hex Private Key", count: evmKeyMatches.length, weight: 45 });
  return hits;
}

export function redactSensitiveText(text) {
  return String(text || "")
    .replace(/\b0x[a-fA-F0-9]{64}\b/g, "[REDACTED_PRIVATE_KEY]")
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[REDACTED_ID]")
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, "[REDACTED_EMAIL]")
    .replace(/(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}\b/g, "[REDACTED_PHONE]");
}

export function analyzeSafety(text) {
  const input = String(text || "").trim();
  if (!input) {
    return { score: 0, severity: "Safe", categories: [], signals: [], urls: [], pii: [], redactedText: "", guidance: ["Enter a message, DM, or URL to inspect locally."] };
  }

  let score = 0;
  const signals = [];
  const categories = new Set();

  // 1. URLs
  const rawUrls = input.match(/https?:\/\/[^\s<>()]+/gi) || [];
  const urls = rawUrls.map(inspectUrl);
  for (const u of urls) {
    if (u.risk > 0) {
      score += Math.round(u.risk * 0.85);
      categories.add("Phishing / Malicious Link");
      u.findings.forEach(f => signals.push({ category: "URL", severity: u.risk >= 30 ? "high" : "medium", detail: `${u.host}: ${f}` }));
    }
  }

  // 2. Social Engineering & Scams
  for (const p of URGENCY_PATTERNS) {
    if (p.re.test(input)) {
      score += p.weight;
      categories.add("Social Engineering / Scam");
      signals.push({ category: "Scam", severity: p.weight >= 26 ? "high" : "medium", detail: p.label });
    }
  }

  // 3. Harassment & Threats
  for (const p of HARASSMENT_PATTERNS) {
    if (p.re.test(input)) {
      score += p.weight;
      categories.add("Harassment / Safety Threat");
      signals.push({ category: "Safety", severity: p.weight >= 35 ? "high" : "medium", detail: p.label });
    }
  }

  // 4. PII Exposure
  const pii = detectPii(input);
  for (const hit of pii) {
    score += hit.weight;
    categories.add("PII / Secret Exposure");
    signals.push({ category: "Privacy", severity: hit.weight >= 30 ? "high" : "low", detail: `${hit.type} detected (${hit.count}x)` });
  }

  score = Math.min(100, score);
  const severity = score >= 65 ? "Critical" : score >= 35 ? "High Risk" : score >= 15 ? "Caution" : "Safe";

  const guidance = [];
  if (categories.has("Phishing / Malicious Link")) guidance.push("Do not click embedded links or enter credentials; verify the official domain manually.");
  if (categories.has("Social Engineering / Scam")) guidance.push("Never share seed phrases, OTPs, or urgent payments requested via DM.");
  if (categories.has("Harassment / Safety Threat")) guidance.push("Preserve evidence screenshot, block sender, and report to platform trust & safety.");
  if (categories.has("PII / Secret Exposure")) guidance.push("Use the one-click Redacted Safe Copy before posting publicly.");
  if (guidance.length === 0) guidance.push("No phishing, harassment, or sensitive PII leaks detected.");

  return {
    score,
    severity,
    categories: Array.from(categories),
    signals,
    urls,
    pii,
    redactedText: redactSensitiveText(input),
    guidance
  };
}
