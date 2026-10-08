# Cloudflare private D1 gateway — NOT DEPLOYED

## Security boundary

The running Cloudflare Worker remains src/cloudflare-pilot.mjs and responds only to /health.
The new modules src/cloudflare-private-gateway.mjs and src/cloudflare-private-ledger.mjs
are NOT imported by the running Worker and are NOT configured in wrangler.jsonc.
No web scraping, outbound form/email submission or actual lead ingestion is enabled.

This is a prototype of a private encrypted-report ledger to be deployed only
after separate owner authorization and a Cloudflare D1 security review.

## Before enabling (not yet authorized)

- Create a **private D1 database** using the Cloudflare Workers Free account only.
- Review migration migrations/0001_private_ledger.sql before a manual apply.
- Bind that database as env.DB to an isolated, non-public test Worker.
- Supply secrets through Cloudflare Secrets, never source code or GitHub commits:
  - STORAGE_ONLY_ENABLED must equal I_UNDERSTAND_PRIVATE_STORAGE_ONLY.
  - AUTH_TOKEN_SHA256: SHA256 hex of a fresh random 256-bit or stronger bearer token.
  - PUBLIC_KEY_FINGERPRINT: lowercase SHA256 hex of an independently managed live RSA-3072 public key.
  - MAX_REQUESTS_PER_DAY: an integer from 1 to 25.
- No private key ever reaches Cloudflare, the browser, or public GitHub.
- Caller encrypts the report outside Cloudflare with a private-key-backed RSA-3072
  public key before upload; the gateway checks structure and fingerprint but
  **cannot prove the caller used that key cryptographically**.
- Authorization uses a bearer token header, never a URL query.
- Access responses contain encrypted envelopes only. No CORS wildcard, no caching.
- Reservation quota is enforced by a single atomic D1 SQL statement across concurrent requests.
  This quota reserves **research budget slots** but does NOT enable or schedule
  real website requests. No public scan endpoint exists.

## Operational restrictions

- Hard maximum 25 reservations per UTC day, configurable lower.
- No unencrypted business names, email addresses, contact URLs or raw HTML in D1.
- No background scheduling, no cron, no public logs or public artifacts.
- Historical US audit ZIP archives must remain outside this public repo
  and should not be uploaded to Cloudflare before a private import plan is approved.
- Public cloudflare-pilot.mjs does not have DB bindings and must stay unmodified.
- D1 migrations, secrets, real research, Cloudflare deployments and live data
  operations each need explicit owner review first.
- D1 Free plan limits are enforced, not a promise of unlimited commercial scraping.

## Offline testing

The GitHub public repository tests only synthetic fixture data.
The test suite mocks D1 behavior and independently tests the atomic SQL statements
in an in-memory SQLite database. Those tests never open real websites or write
to any external Cloudflare database.

See the Cloudflare Docs for D1 limits, Worker bindings and SQL prepared statements.
