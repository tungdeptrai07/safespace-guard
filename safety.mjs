export function analyzeSafety(text) {
  const s = String(text || "").toLowerCase();
  const flags = [];
  if (/\b(urgent|verify your account|seed phrase|password|click here now)\b/.test(s)) flags.push("Phishing / Social Engineering");
  if (/\b(kill|harm|worthless|doxx|threat)\b/.test(s)) flags.push("Harassment / Harmful Language");
  return { safe: flags.length === 0, flags };
}
