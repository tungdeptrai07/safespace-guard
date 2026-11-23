# SafeSpace Guard — Local-First Digital Safety, Phishing & Privacy Shield

> Built for **SafeSpace Hacks 2026** | Live App: **[tungdeptrai07.github.io/safespace-guard](https://tungdeptrai07.github.io/safespace-guard/)**

**SafeSpace Guard** protects students, creators, and online communities from phishing URLs, typosquatted brand spoofing, social-engineering scams, doxxing/harassment threats, and accidental PII leaks—running **100% locally in the browser** with zero third-party telemetry.

## Core Capabilities
- **Multi-Signal URL Security Analyzer (`inspectUrl`):** Detects punycode/Unicode homograph attacks, raw IPv4 hosts, embedded `@` redirects, high-abuse TLDs, deep subdomain chains, and Levenshtein-distance typosquatting against major platforms.
- **Social-Engineering & Harassment Classifier (`analyzeSafety`):** Flags credential/seed-phrase extraction lures, countdown threats, doxxing/blackmail threats, and targeted abuse with explainable evidence badges and 0–100 severity scoring.
- **One-Click PII & Secret Redactor (`redactSensitiveText`):** Automatically detects and scrubs emails, phone numbers, SSNs/IDs, and 64-hex private keys before sharing screenshots or incident reports.
- **JSON Incident Report Export:** Download structured evidence reports for platform Trust & Safety teams.

## Automated Unit Tests
```bash
node --test safety.test.mjs
```
