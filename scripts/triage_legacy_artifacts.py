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
MAX_ARCHIVE_BYTES = 160 * 1024 * 1024
MAX_ARCHIVE_ENTRIES = 128
SOURCES = {
    "CORE": "overture-us-core-full-audit-results.json",
    "NEAR_CORE": "overture-us-near-core-full-audit-results.json",
    "ADJACENT": "overture-us-adjacent-full-audit-results.json",
}
QUEUE_KIND = {
    "NEEDS_REVIEW": (0, "FORM_PURPOSE_REVIEW"),
    "CONTACT_CHANNEL_REVIEW": (0, "CONTACT_CHANNEL_HUMAN_REVIEW"),
    "WRONG_FORM_PURPOSE": (0, "FORM_PURPOSE_REVIEW"),
    "NO_GENERAL_FORM": (1, "EXTENDED_CONTACT_RECHECK"),
    "NOT_RELEVANT_ENGLISH_EVIDENCE": (2, "TARGET_RELEVANCE_RECHECK"),
    "CAPTCHA_MANUAL_REVIEW": (3, "CAPTCHA_HUMAN_REVIEW_ONLY"),
    "GET_US_EXTERNAL_REDIRECT_BLOCKED": (4, "EXTERNAL_REDIRECT_HUMAN_REVIEW"),
    "GET_HTTP_404": (5, "UNAVAILABLE_SITE_HUMAN_REVIEW"),
    # Historical labels created by regex heuristics are not proof of legal exclusion.
    "US_NONPROFIT": (0, "ENTITY_CLASSIFICATION_HUMAN_REVIEW_ONLY"),
    "US_RELIGIOUS_ORGANIZATION": (0, "ENTITY_CLASSIFICATION_HUMAN_REVIEW_ONLY"),
    "US_GOVERNMENT_OR_PUBLIC_BODY": (0, "ENTITY_CLASSIFICATION_HUMAN_REVIEW_ONLY"),
    "US_ENTITY_CLASSIFICATION_REVIEW": (0, "ENTITY_CLASSIFICATION_HUMAN_REVIEW_ONLY"),
    "EXCLUDED_TARGET_INDUSTRY": (0, "TARGET_CLASSIFICATION_HUMAN_REVIEW_ONLY"),
    "EXCLUDED_COMPETITOR": (0, "TARGET_CLASSIFICATION_HUMAN_REVIEW_ONLY"),
    "EXCLUDED_PORTAL": (0, "TARGET_CLASSIFICATION_HUMAN_REVIEW_ONLY"),
    "EXCLUDED_MAGAZINE_PUBLISHER": (0, "TARGET_CLASSIFICATION_HUMAN_REVIEW_ONLY"),
    "GET_US_TOO_MANY_REDIRECTS": (0, "REDIRECT_LOOP_HUMAN_REVIEW_ONLY"),
    "ACCESS_RESTRICTED": (0, "ACCESS_RESTRICTED_HUMAN_REVIEW_ONLY"),
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
    "SOLICITATION_PROHIBITED", "AUTOMATION_PROHIBITED",
    "GET_FINAL_URL_UNSAFE", "OUTREACH_DISCOVERY_WEBSITE_UNSAFE",
}
# Any explicit threat, suppression or prior confirmed candidature takes precedence
# over older/staler, more permissive checkpoints for the same canonical host.
HARD_VETO_LABELS = frozenset({
    "EXPLICITLY_RESTRICTED_OR_TERMINAL",
    "OFFICIAL_GOVERNMENT_DOMAIN_EXCLUDED",
    "PRESENT_IN_EXISTING_INVENTORY",
})
# This eligibility is for a separately owner-approved READ-ONLY inspection only,
# not for an outbound submit and not authorization to start the network.
NETWORK_RECHECK_LABELS = frozenset({
    "EXTENDED_CONTACT_RECHECK", "TARGET_RELEVANCE_RECHECK", "SAFE_NETWORK_RECHECK"
})
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
    if status in PERMANENT_RESTRICTIONS:
        return (99, "EXPLICITLY_RESTRICTED_OR_TERMINAL")
    if status.startswith("TERMINAL_"):
        # Retry exhaustion is a release-level observation, NOT proof of an
        # illegal site. Clearly unsafe/policy-terminal statuses remain blocked.
        if any(x in status for x in
               ("THREAT", "PRIVATE_ADDRESS", "UNSAFE", "PROHIBITED", "SOLICITATION")):
            return (99, "EXPLICITLY_RESTRICTED_OR_TERMINAL")
        return (0, "RETRY_EXHAUSTED_HUMAN_REVIEW_ONLY")
    if is_eligible or status == "SITE_FORM_ELIGIBLE_PRE_COMPLIANCE":
        # A previously accepted form absent from current inventory must be
        # reconciled manually; never silently disappear or become SEND_READY.
        return (0, "PRECOMPLIANCE_INVENTORY_RECONCILIATION")
    if status in QUEUE_KIND:
        return QUEUE_KIND[status]
    if status in NETWORK_RETRY:
        return (6, "SAFE_NETWORK_RECHECK")
    m = re.fullmatch(r"GET_HTTP_(\d{3})", status)
    if m:
        code = int(m[1])
        if code in (408, 425, 429) or 500 <= code <= 599:
            return (6, "SAFE_NETWORK_RECHECK")
        return (0, "HTTP_NONRETRYABLE_HUMAN_REVIEW_ONLY")
    return (0, "UNKNOWN_STATUS_HUMAN_REVIEW_ONLY")



def open_bounded_zip(archive: Path) -> zipfile.ZipFile:
    """Refuse excessive ZIP containers and member-count bombs before decoding."""
    if archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise ValueError("ZIP_CONTAINER_TOO_LARGE")
    z = zipfile.ZipFile(archive)
    if len(z.filelist) > MAX_ARCHIVE_ENTRIES:
        z.close()
        raise ValueError("ZIP_MEMBER_COUNT_TOO_LARGE")
    return z


def streamed_file_sha256(archive: Path) -> str:
    """Avoid loading whole input archives into RAM merely to hash them."""
    digest = hashlib.sha256()
    size = 0
    with archive.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            if size > MAX_ARCHIVE_BYTES:
                raise ValueError("ZIP_CONTAINER_TOO_LARGE")
            digest.update(chunk)
    return digest.hexdigest()


def inspect_archive(archive: Path) -> tuple[list[dict], str, str]:
    with open_bounded_zip(archive) as z:
        available = [(tier, name) for tier, name in SOURCES.items() if name in z.namelist()]
        if len(available) != 1:
            raise ValueError("EXPECTED_ONE_SUPPORTED_AUDIT_RESULT_FILE")
        tier, member = available[0]
        info = z.getinfo(member)
        if z.namelist().count(member) != 1:
            raise ValueError("DUPLICATE_AUDIT_ARCHIVE_MEMBER")
        if info.file_size > MAX_JSON_SIZE or info.file_size < 2:
            raise ValueError("AUDIT_INPUT_UNCOMPRESSED_TOO_LARGE")
        if not info.compress_size or (info.file_size > 1024 * 1024
                                     and info.file_size > info.compress_size * 500):
            raise ValueError("AUDIT_INPUT_COMPRESSION_RATIO_UNSAFE")
        data = json.loads(z.read(member).decode("utf-8"))
    if not isinstance(data, list) or len(data) > MAX_CANDIDATES:
        raise ValueError("AUDIT_INPUT_COUNT_INVALID")
    return data, tier, streamed_file_sha256(archive)


def load_existing_inventory(archive: Path | None) -> tuple[set[str], str | None]:
    if archive is None:
        return set(), None
    target = "us-precompliance-inventory-export.csv"
    manifest_name = "us-precompliance-inventory-export-manifest.json"
    with open_bounded_zip(archive) as z:
        if z.namelist().count(target) != 1 or z.namelist().count(manifest_name) != 1:
            raise ValueError("INVENTORY_EXPORT_OR_MANIFEST_DUPLICATE_OR_MISSING")
        data_info = z.getinfo(target)
        manifest_info = z.getinfo(manifest_name)
        if (data_info.file_size > 32 * 1024 * 1024 or
            manifest_info.file_size > 64 * 1024 or
            data_info.file_size < 20 or manifest_info.file_size < 2):
            raise ValueError("INVENTORY_ARCHIVE_SIZE_INVALID")
        for info in (data_info, manifest_info):
            if not info.compress_size or (info.file_size > 1024 * 1024
                   and info.file_size > info.compress_size * 500):
                raise ValueError("INVENTORY_COMPRESSION_RATIO_UNSAFE")
        data = z.read(target)
        manifest = json.loads(z.read(manifest_name).decode("utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("INVENTORY_MANIFEST_INVALID")
    digest = manifest.get("csvSha256")
    count = manifest.get("uniqueDomains")
    release = manifest.get("release")
    if (not isinstance(digest, str) or
        not re.fullmatch(r"[0-9a-f]{64}", digest) or
        type(count) is not int or count < 0 or count > MAX_CANDIDATES or
        not isinstance(release, str) or not RELEASE_RE.fullmatch(release)):
        raise ValueError("INVENTORY_MANIFEST_INVALID")
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("INVENTORY_SHA256_MISMATCH")
    reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
    if not reader.fieldnames or not ("normalized_domain" in reader.fieldnames or
                                     "normalizedDomain" in reader.fieldnames):
        raise ValueError("INVENTORY_CSV_SCHEMA_INVALID")
    hosts = {h for row in reader if (h := canonical_host(row))}
    if len(hosts) != count:
        raise ValueError("INVENTORY_ROW_COUNT_MISMATCH")
    return hosts, digest


def selection_rank(priority: int, label: str, row: dict) -> tuple:
    """Deterministic cross-tier severity independent of archive order."""
    if label == "EXPLICITLY_RESTRICTED_OR_TERMINAL":
        band = 0
    elif label == "OFFICIAL_GOVERNMENT_DOMAIN_EXCLUDED":
        band = 1
    elif label == "PRESENT_IN_EXISTING_INVENTORY":
        band = 2
    elif label == "PRECOMPLIANCE_INVENTORY_RECONCILIATION":
        band = 3
    elif label not in NETWORK_RECHECK_LABELS:
        band = 4
    else:
        band = 5
    return (band, priority, str(row.get("status") or ""),
            str(row.get("targetTier") or ""), str(row.get("release") or ""))


def triage(records: list[dict], tier: str, inventory_hosts: set[str] | None = None):
    inventory_hosts = inventory_hosts or set()
    seen: dict[str, tuple[int, str, dict]] = {}
    statuses = Counter()
    dropped_invalid = dropped_duplicate = 0
    for row in records:
        allowed_tiers = ("CORE", "NEAR_CORE", "ADJACENT") if tier == "ALL" else (tier, None)
        if not isinstance(row, dict) or row.get("targetTier") not in allowed_tiers:
            dropped_invalid += 1
            continue
        host = canonical_host(row)
        if not host:
            dropped_invalid += 1
            continue
        status = str(row.get("status", "UNKNOWN"))
        statuses[status] += 1
        priority, label = classify(status, bool(row.get("siteFormEligiblePreCompliance")))
        # .gov / .mil are restricted official TLDs; .us is NOT.
        if host.endswith((".gov", ".mil")) and label != "EXPLICITLY_RESTRICTED_OR_TERMINAL":
            priority, label = (99, "OFFICIAL_GOVERNMENT_DOMAIN_EXCLUDED")
        elif host in inventory_hosts and label not in HARD_VETO_LABELS:
            priority, label = (99, "PRESENT_IN_EXISTING_INVENTORY")
        previous = seen.get(host)
        if previous:
            dropped_duplicate += 1
            if selection_rank(*previous) <= selection_rank(priority, label, row):
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
            # Review-only states are retained in the ledger, not discarded.
            # NO label here constitutes live site-access or outbound approval.
            "networkRecheckEligible": label in NETWORK_RECHECK_LABELS,
            "sendAuthorized": False,
            "host": host,
            "https_origin": "https://" + host + "/",
            "previous_status": str(row.get("status", "")),
            "tier": str(row.get("targetTier") or tier),
            "release": str(row.get("release", "")),
            "state": str(row.get("stateCode") or "")[:2],
            "taxonomy": str(row.get("taxonomyPrimary") or "")[:90],
        })
    queue.sort(key=lambda item: (item["priority"], item["tier"], item["host"]))
    return queue, dict(sorted(groups.items())), dict(sorted(statuses.items())), dropped_invalid, dropped_duplicate


def combine_private_audits(archives: list[tuple[list[dict], str, str]]):
    """Merge real source snapshots before triage so a cross-tier danger veto wins.

    The full input remains local; only file hashes and counts are safe to report.
    """
    if not archives or len(archives) > 12:
        raise ValueError("AUDIT_ARCHIVE_COUNT_UNSUPPORTED")
    combined = []
    manifests = []
    hashes = set()
    for records, tier, sha in archives:
        if tier not in SOURCES or sha in hashes:
            raise ValueError("DUPLICATE_OR_INVALID_AUDIT_SOURCE")
        hashes.add(sha)
        if len(combined) + len(records) > MAX_CANDIDATES:
            raise ValueError("COMBINED_AUDIT_INPUT_TOO_LARGE")
        for record in records:
            if not isinstance(record, dict):
                combined.append(record)
                continue
            if record.get("targetTier") not in (None, tier):
                raise ValueError("TIER_CROSSING_AUDIT_RECORD")
            combined.append({**record, "targetTier": tier})
        manifests.append({"tier": tier, "artifactSha256": sha, "inputRecords": len(records)})
    return combined, manifests


def write_private(path: Path, content: str) -> None:
    # Plaintext queue MUST be inaccessible to other OS users, never sent to CI.
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
        f.write(content)


def cli() -> None:
    p = argparse.ArgumentParser(description="Offline legacy audit triage. NEVER a send-ready report.")
    p.add_argument("--audit-zip", type=Path, action="append", required=True,
                   help="Repeat for CORE, NEAR_CORE and ADJACENT snapshots.")
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
    audits = [inspect_archive(p) for p in args.audit_zip]
    records, source_manifests = combine_private_audits(audits)
    tier = audits[0][1] if len(audits) == 1 else "ALL"
    previous, inventory_hash = load_existing_inventory(args.inventory_zip)
    queue, categories, statuses, invalid, duplicates = triage(records, tier, previous)
    if any(not RELEASE_RE.fullmatch(str(row.get("release", ""))) for row in queue):
        raise ValueError("RELEASE_INVALID")
    columns = ["priority", "queue_kind", "networkRecheckEligible", "sendAuthorized", "host",
               "https_origin", "previous_status", "tier", "release", "state", "taxonomy"]
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
        "manualReviewOnlyDomains": sum(n for k, n in categories.items()
                                       if k not in HARD_VETO_LABELS and k not in NETWORK_RECHECK_LABELS),
        "sendAuthorizedDomains": 0,
        "sourceArtifactSha256": source_manifests[0]["artifactSha256"] if len(audits) == 1 else None,
        "sourceArtifacts": source_manifests, "inventoryCsvSha256": inventory_hash,
        "candidateWebsiteAccessPerformed": False, "outboundSubmissionPerformed": False,
        "productionDatabaseWritePerformed": False, "openAiApiUsed": False, "paidApiUsed": False,
        "caution": "These are historical snapshots; recheck results may have changed. No candidate is approved for outreach.",
    }
    write_private(out / "PRIVATE_RECHECK_SUMMARY.json", json.dumps(summary, ensure_ascii=False, indent=2) + "\n")
    # No source URLs or hosts are ever printed in terminal logs.
    print(json.dumps({"event": "OFFLINE_US_AUDIT_TRIAGE", "inputRecords": len(records),
                      "uniqueQueueDomains": len(queue), "sourceTier": tier,
                      "sourceArchiveCount": len(audits),
                      "privateFilesOnly": True, "sendAuthorized": False}))


if __name__ == "__main__":
    cli()