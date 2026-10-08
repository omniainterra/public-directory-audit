#!/usr/bin/env python3
"""Offline triage of historic US site-audit artifacts.

This utility never resolves DNS, performs HTTP, submits forms, sends emails or
writes to a Production database. Historical statuses are evidence for a
future REVIEW, never authorization to contact a business.

Run only on private local or isolated compute, not within public GitHub Actions.
Output may contain business contact URLs and must NOT be committed or uploaded
as a public workflow artifact.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

MAX_JSON_SIZE = 80 * 1024 * 1024
MAX_CANDIDATES = 200_000
SOURCES = {
    "CORE": "overture-us-core-full-audit-results.json",
    "NEAR_CORE": "overture-us-near-core-full-audit-results.json",
    "ADJACENT": "overture-us-adjacent-full-audit-results.json",
}
QUEUE_KIND = {
    "NEEDS_REVIEW": (0, "FORM_PURPOSE_REVIEW"),
    "WRONG_FORM_PURPOSE": (0, "FORM_PURPOSE_REVIEW"),
    "NO_GENERAL_FORM": (1, "EXTENDED_CONTACT_RECHECK"),
    "NOT_RELEVANT_ENGLISH_EVIDENCE": (2, "TARGET_RELEVANCE_RECHECK"),
    "CAPTCHA_MANUAL_REVIEW": (3, "CAPTCHA_HUMAN_REVIEW_ONLY"),
    "GET_US_EXTERNAL_REDIRECT_BLOCKED": (4, "EXTERNAL_REDIRECT_HUMAN_REVIEW"),
    "GET_HTTP_404": (5, "UNAVAILABLE_SITE_HUMAN_REVIEW"),
}
NETWORK_RETRY = {
    "GET_Error", "GET_US_NETWORK_ERROR", "GET_US_DNS_ERROR", "GET_US_DNS_EMPTY",
    "GET_US_TIMEOUT", "GET_US_RESPONSE_ERROR", "GET_US_RESPONSE_ABORTED",
    "GET_US_ABORTED", "GET_BODY_UNREADABLE", "AUDIT_EXCEPTION",
    "OUTREACH_DISCOVERY_POLICY_PAGE_UNREADABLE",
}
PERMANENT_RESTRICTIONS = {
    "GET_US_THREAT_BLOCKED", "GET_US_PRIVATE_ADDRESS_BLOCKED",
    "US_SOLICITATION_PROHIBITED", "US_AUTOMATION_PROHIBITED",
    "US_GOVERNMENT_OR_PUBLIC_BODY", "US_RELIGIOUS_ORGANIZATION",
    "US_NONPROFIT", "EXCLUDED_TARGET_INDUSTRY", "EXCLUDED_COMPETITOR",
    "EXCLUDED_PORTAL", "SOLICITATION_PROHIBITED", "AUTOMATION_PROHIBITED",
    "GET_FINAL_URL_UNSAFE", "OUTREACH_DISCOVERY_WEBSITE_UNSAFE",
}
RELEASE_RE = re.compile(r"^20\d{2}-\d{2}-\d{2}\.\d+$")


def canonical_host(record: dict) -> str | None:
    raw = str(record.get("normalizedDomain") or record.get("normalized_domain") or "").strip().lower()
    raw = raw.removeprefix("www.").rstrip(".")
    if len(raw) > 253 or not re.fullmatch(r"[a-z0-9._-]+", raw):
        return None
    if "." not in raw or raw.endswith((".local", ".internal", ".test")):
        return None
    if raw.startswith(".") or ".." in raw or "_" in raw:
        return None
    # Reject nonstandard numeric IPv4 shorthands (127.1, 0x7f.0.0.1)
    # which some URL/DNS stacks may reinterpret as local IP addresses.
    if all(re.fullmatch(r"(?:0x[0-9a-f]+|[0-9]+)", label)
           for label in raw.split(".")):
        return None
    if raw.rsplit(".", 1)[-1].isdigit():
        return None
    try:
        ipaddress.ip_address(raw)
        return None
    except ValueError:
        pass
    return raw


def classify(status: str, is_eligible: bool) -> tuple[int, str]:
    """No status here ever constitutes SEND/READY eligibility."""
    if is_eligible and status == "SITE_FORM_ELIGIBLE_PRE_COMPLIANCE":
        return (99, "ALREADY_PRECOMPLIANCE_CANDIDATE")
    if status in PERMANENT_RESTRICTIONS or status.startswith("TERMINAL_"):
        return (99, "EXPLICITLY_RESTRICTED_OR_TERMINAL")
    if status in QUEUE_KIND:
        return QUEUE_KIND[status]
    if status in NETWORK_RETRY:
        return (6, "SAFE_NETWORK_RECHECK")
    m = re.fullmatch(r"GET_HTTP_(\d{3})", status)
    if m:
        code = int(m[1])
        if code in (408, 425, 429) or 500 <= code <= 599:
            return (6, "SAFE_NETWORK_RECHECK")
        return (99, "HTTP_PERMANENT_OR_POLICY_BLOCKED")
    return (99, "NOT_QUEUED")


def inspect_archive(archive: Path) -> tuple[list[dict], str, str]:
    with zipfile.ZipFile(archive) as z:
        available = [(tier, name) for tier, name in SOURCES.items() if name in z.namelist()]
        if len(available) != 1:
            raise ValueError("EXPECTED_ONE_SUPPORTED_AUDIT_RESULT_FILE")
        tier, member = available[0]
        info = z.getinfo(member)
        if info.file_size > MAX_JSON_SIZE:
            raise ValueError("AUDIT_INPUT_UNCOMPRESSED_TOO_LARGE")
        data = json.loads(z.read(member).decode("utf-8"))
    if not isinstance(data, list) or len(data) > MAX_CANDIDATES:
        raise ValueError("AUDIT_INPUT_COUNT_INVALID")
    return data, tier, hashlib.sha256(archive.read_bytes()).hexdigest()


def load_existing_inventory(archive: Path | None) -> tuple[set[str], str | None]:
    if archive is None:
        return set(), None
    with zipfile.ZipFile(archive) as z:
        target = "us-precompliance-inventory-export.csv"
        manifest_name = "us-precompliance-inventory-export-manifest.json"
        if target not in z.namelist() or manifest_name not in z.namelist():
            raise ValueError("INVENTORY_EXPORT_OR_MANIFEST_MISSING")
        data = z.read(target)
        manifest = json.loads(z.read(manifest_name).decode("utf-8"))
    if hashlib.sha256(data).hexdigest() != manifest.get("csvSha256"):
        raise ValueError("INVENTORY_SHA256_MISMATCH")
    rows = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
    hosts = {h for row in rows if (h := canonical_host(row))}
    if len(hosts) != manifest.get("uniqueDomains"):
        raise ValueError("INVENTORY_ROW_COUNT_MISMATCH")
    return hosts, manifest.get("csvSha256")


def triage(records: list[dict], tier: str, inventory_hosts: set[str] | None = None):
    inventory_hosts = inventory_hosts or set()
    seen: dict[str, tuple[int, str, dict]] = {}
    statuses = Counter()
    dropped_invalid = dropped_duplicate = 0
    for row in records:
        if not isinstance(row, dict) or row.get("targetTier") not in (tier, None):
            dropped_invalid += 1
            continue
        host = canonical_host(row)
        if not host:
            dropped_invalid += 1
            continue
        status = str(row.get("status", "UNKNOWN"))
        statuses[status] += 1
        priority, label = classify(status, bool(row.get("siteFormEligiblePreCompliance")))
        if host in inventory_hosts:
            priority, label = (99, "PRESENT_IN_EXISTING_INVENTORY")
        previous = seen.get(host)
        if previous:
            dropped_duplicate += 1
            if (priority, host) >= (previous[0], host):
                continue
        seen[host] = (priority, label, row)
    groups = Counter(label for _, label, _ in seen.values())
    queue = []
    for host, (priority, label, row) in seen.items():
        if priority >= 99:
            continue
        # Only the canonical HTTPS origin is included. No embedded redirect,
        # userinfo, query or path is ever carried into a future network worker.
        queue.append({
            "priority": priority,
            "queue_kind": label,
            "host": host,
            "https_origin": "https://" + host + "/",
            "previous_status": str(row.get("status", "")),
            "tier": tier,
            "release": str(row.get("release", "")),
            "state": str(row.get("stateCode") or "")[:2],
            "taxonomy": str(row.get("taxonomyPrimary") or "")[:90],
        })
    queue.sort(key=lambda item: (item["priority"], item["tier"], item["host"]))
    return queue, dict(sorted(groups.items())), dict(sorted(statuses.items())), dropped_invalid, dropped_duplicate


def write_private(path: Path, content: str) -> None:
    # Plaintext queue MUST be inaccessible to other OS users, never sent to CI.
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
        f.write(content)


def cli() -> None:
    p = argparse.ArgumentParser(description="Offline legacy audit triage. NEVER a send-ready report.")
    p.add_argument("--audit-zip", type=Path, required=True)
    p.add_argument("--inventory-zip", type=Path)
    p.add_argument("--private-out", type=Path, required=True)
    args = p.parse_args()
    if os.getenv("GITHUB_ACTIONS") == "true":
        raise SystemExit("PUBLIC_GITHUB_ACTIONS_PRIVATE_DATA_PROCESSING_DENIED")
    out = args.private_out.resolve()
    checkout = Path(__file__).resolve().parents[1]
    if not out.is_absolute() or out == checkout or checkout in out.parents:
        raise SystemExit("PRIVATE_OUTPUT_MUST_NOT_BE_UNDER_PUBLIC_REPOSITORY")
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(out, 0o700)
    records, tier, audit_hash = inspect_archive(args.audit_zip)
    previous, inventory_hash = load_existing_inventory(args.inventory_zip)
    queue, categories, statuses, invalid, duplicates = triage(records, tier, previous)
    if any(not RELEASE_RE.fullmatch(str(row.get("release", ""))) for row in queue):
        raise ValueError("RELEASE_INVALID")
    columns = ["priority", "queue_kind", "host", "https_origin", "previous_status", "tier", "release", "state", "taxonomy"]
    text = io.StringIO(newline="")
    writer = csv.DictWriter(text, fieldnames=columns, lineterminator="\n")
    writer.writeheader()
    writer.writerows(queue)
    write_private(out / "PRIVATE_RECHECK_QUEUE.csv", text.getvalue())
    # Summary deliberately excludes individual domains, names, phone numbers and URLs.
    summary = {
        "version": 1, "classification": "OFFLINE_RECHECK_QUEUE_NOT_SEND_READY",
        "sourceTier": tier, "inputRecords": len(records), "uniqueQueueDomains": len(queue),
        "previouslyConfirmedInventoryExcluded": len(previous),
        "duplicateAuditDomainRowsCollapsed": duplicates, "invalidAuditRows": invalid,
        "groupCounts": categories, "statusCounts": statuses,
        "sourceArtifactSha256": audit_hash, "inventoryCsvSha256": inventory_hash,
        "candidateWebsiteAccessPerformed": False, "outboundSubmissionPerformed": False,
        "productionDatabaseWritePerformed": False, "openAiApiUsed": False, "paidApiUsed": False,
        "caution": "These are historical snapshots; recheck results may have changed. No candidate is approved for outreach.",
    }
    write_private(out / "PRIVATE_RECHECK_SUMMARY.json", json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    # No source URLs or hosts are ever printed in terminal logs.
    print(json.dumps({"event": "OFFLINE_US_AUDIT_TRIAGE", "inputRecords": len(records),
                      "uniqueQueueDomains": len(queue), "sourceTier": tier,
                      "privateFilesOnly": True, "sendAuthorized": False}))


if __name__ == "__main__":
    cli()