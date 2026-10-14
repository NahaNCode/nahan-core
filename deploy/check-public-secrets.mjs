import {execFileSync} from 'node:child_process';
import {readFileSync} from 'node:fs';

const rules = {
  privateKey: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----/,
  githubToken: /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{50,})\b/,
  gitlabToken: /\bglpat-[A-Za-z0-9_-]{20,}\b/,
  awsKey: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/,
  jwt: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}\b/,
  credentialLiteral: /["'](?:password|token|apiKey|secret|privateKey)["']\s*:\s*["'][A-Za-z0-9_+\/=.-]{24,}["']/i,
};
let failed = false;
for (const path of execFileSync('git', ['ls-files', '-z']).toString().split('\0').filter(Boolean)) {
  const content = readFileSync(path, 'utf8');
  for (const [rule, pattern] of Object.entries(rules)) {
    if (!pattern.test(content)) continue;
    // Report locations only; CI must not echo a discovered credential.
    console.error(`${path}: possible ${rule}; remove or replace with generated test data`);
    failed = true;
  }
}
if (failed) process.exit(1);
