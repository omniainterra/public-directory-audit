# Security boundaries

This repository contains a separately publishable, **credential-free software prototype**.
GitHub Actions are for software tests only. **Never use GitHub-hosted Actions
for the ongoing commercial collection of sales leads** or as an inexpensive server
replacement; refer to GitHub Actions Additional Product Terms.

- No customer data, production source, private company repository URLs, shared databases, API keys or personal access tokens.
- CI jobs run offline synthetic tests on standard `ubuntu-24.04`. No self-hosted/Windows, no scheduled runs, no live crawling, no CI artifacts.
- Do not add a workflow that calls `discover_overture.py` or `--mode live`.
- In a separately permitted, authorized compute environment only, prototype discovery can be run with an explicit manual approval phrase.
- No Javascript or HTML from target pages is executed; no forms are submitted.
- Deny private/multicast/reserved IPs, require validated HTTPS and pinned public DNS, stop cross-host redirects, cap responses, respect robots.txt and refuse unsafe hosts using publicly maintained threat feeds.
- Fail closed when any required threat feed or robots policy cannot be read.
- Research-only categories never mean send-authorized; the legal review and outbound delivery are separate.
- Public repository code and logs can be seen by anyone. Never commit the separately delivered **private RSA key** or decrypted audit output.
- The committed `public-key.pem` is for artificial test data only. Live research requires `RESEARCH_PUBLIC_KEY_PATH` outside the repository and a corresponding private key held securely by its owner; never encrypt actual contacts under this test key.
- Reports are AES-256-GCM authenticated ciphertext with a one-time random data key wrapped by RSA-3072-OAEP-SHA256. Store only encrypted output if using any shared artifact service, under its storage quotas.
- Continuously monitor service/provider policies, traffic limits and data protection requirements.

Live scanning is explicitly blocked when `GITHUB_ACTIONS=true` or on Windows.


## Latest fail-closed threat screening

The Node.js and Cloudflare research prototypes must be provided with independently validated threat intelligence from CERT.PL, Phishing Database and URLHaus, confirmed within the past 24 hours. Five endpoint-security-blocked domains are denied even when a caller passes an empty list. Missing or stale evidence prevents candidate website requests. These checks do not guarantee complete malware detection. An isolated, authorized Linux runtime is still required for any prospective live research.
