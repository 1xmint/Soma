export const PATTERNS = [
  { name: 'Generic key (sk-)',             re: /\bsk-[A-Za-z0-9_\-]{20,}\b/ },
  { name: 'Generic key (pk-)',             re: /\bpk-[A-Za-z0-9_\-]{20,}\b/ },
  { name: 'Generic key (cn-)',             re: /\bcn-[A-Za-z0-9_\-]{20,}\b/ },
  { name: 'Private key header',            re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },
  { name: 'AWS access key (AKIA)',         re: /\bAKIA[0-9A-Z]{16}\b/ },
  { name: 'GitHub token (ghp_)',           re: /\bghp_[A-Za-z0-9]{36}\b/ },
  { name: 'GitHub PAT (github_pat_)',      re: /\bgithub_pat_[A-Za-z0-9_]{82}\b/ },
  { name: 'Anthropic key (sk-ant-)',       re: /\bsk-ant-[A-Za-z0-9\-_]{40,}\b/ },
  { name: 'Secret env var w/ long value',  re: /(?:SECRET|_KEY|_TOKEN|_PASS|_AUTH|_CRED)[_A-Z0-9]*\s*=\s*["']?[A-Za-z0-9+/]{40,}=*["']?/i },
];

const NOSCAN = /noscan/i;

/**
 * Scan file content for secret patterns.
 * Lines containing "noscan" (any case) are skipped — use as inline suppression.
 * @param {string} content
 * @returns {{ line: number; pattern: string; text: string }[]}
 */
export function scan(content) {
  const findings = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (NOSCAN.test(lines[i])) continue;
    for (const { name, re } of PATTERNS) {
      if (re.test(lines[i])) {
        findings.push({ line: i + 1, pattern: name, text: lines[i].trim().slice(0, 120) });
        break;
      }
    }
  }
  return findings;
}
