# Security Policy

## About This Tool

This is a **defensive** security tool. It analyzes email files (`.eml`) to detect phishing indicators — it does not send email, exploit anything, or perform offensive actions. It is intended for:

- Analyzing suspicious emails you have received
- Security awareness training and education
- SOC / detection-engineering learning and experimentation
- Research against public phishing corpora

## Handling Malicious Content

This tool is designed to parse content that may be malicious by nature (phishing emails, suspicious URLs, disguised attachments). Important safety notes:

- The analyzer **never executes** attachments or fetches URLs from analyzed emails — it inspects metadata, extensions, and structure only.
- Attachment analysis hashes files (SHA256) for VirusTotal lookups; it does not open or run them.
- When pasting real phishing emails into the web interface, the content is analyzed **in memory** and never written to disk or logged.
- Do not use this tool as your only line of defense. It is a heuristic analyzer with a measured ~73% detection rate on the Nazario corpus, not a complete email-security solution.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please **do not** open a public GitHub issue. Instead, report it privately:

- Via [GitHub Security Advisories](https://github.com/AhmedDAH1/email-threat-analyzer/security/advisories), or
- Via [LinkedIn](https://www.linkedin.com/in/ahmed-dahdouh)

I will acknowledge receipt within 72 hours and coordinate a fix before any public disclosure.

## Scope and Limitations

This is a learning project for a portfolio. It is **not intended for production email-security deployment** without further hardening. Specifically:

- The web interface has no authentication — do not expose it to untrusted networks
- Detection is structural/heuristic, not semantic — plain-text social-engineering with no URLs, attachments, or spoofed headers may not be flagged
- The hosted demo runs with VirusTotal disabled (no API key, rate limits)

## Credentials and API Keys

The optional VirusTotal integration requires an API key, passed via the `--virustotal` CLI flag or an environment variable. **Never commit API keys to the repository.** If you find a committed credential in the project history, please report it privately so it can be revoked.

## Sample Data

The bundled `samples/real/` directory contains real phishing emails with all recipient addresses anonymized to `username@domain.com`. The larger Nazario corpus used for validation is **not** redistributed in this repository.
