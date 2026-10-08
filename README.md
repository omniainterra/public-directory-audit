# Public Directory Audit — isolated research software

This is an independent, credential-free research program for public business directories. No connection to any production customer database or private commercial repository is included.

## What is included

- An offline test suite and synthetic sample data, suitable for **standard GitHub-hosted Linux CI in this public repository**.
- A separate, strictly capped Overture Maps public-data collector (`scripts/discover_overture.py`) and HTTPS-only inspector for later evaluation **in an independently authorized Linux environment**.
- A strict network safety model: DNS pinning, non-public IP restrictions, no cross-host redirects, `robots.txt` checks, phishing/threat denylist, static HTML only, no JavaScript execution, no form submission.
- Encryption of any research output using RSA-OAEP and AES-GCM. The private key is **never** part of this repository. The included `public-key.pem` is **only for synthetic software tests**; live research requires a separately managed RSA-3072 public key outside the repository, for which the research operator securely holds the corresponding private key.

## Important limitations

**GitHub Actions here performs software testing ONLY.** GitHub's Additional Product Terms do not permit using GitHub-hosted Actions as a general-purpose replacement for commercial data-collection compute. Do not add crawling or scheduled harvesting to `.github/workflows/`.

This project does **not** confirm the legal eligibility of advertising through a business contact form, and does not produce `READY` or `SEND` records. No high-volume collection rate or yield improvement has yet been verified against live websites.

## Safe offline software tests

Node.js 22+ is required. The tests are self-contained with no external packages or prospect visits:

```sh
npm test
npm run smoke
```

The smoke output is AES-GCM encrypted. The sample input is synthetic, never a live lead list.

## Independent research evaluation (separate compute provider)

The raw-data collector and the inspector are supplied as source code but intentionally blocked from running against real websites on Windows or inside GitHub Actions. They require a separately permitted Linux compute environment, owner approval, and an explicitly configured `RESEARCH_PUBLIC_KEY_PATH` pointing to a separately managed RSA-3072 public key **outside** the checked-out repository. The default site limit is ten; the hard cap is 25 per pilot. No background scheduling is implemented.

See [SECURITY.md](SECURITY.md) and [docs/SETUP-JA.md](docs/SETUP-JA.md).

## Data origin

Overture Maps Places is published as public GeoParquet: <https://docs.overturemaps.org/getting-data/>. Querying the public source and processing individual business websites are separate stages with separate operating rules.

## License

No open-source license is granted by this repository. Public availability does not imply permission to reuse its code.
