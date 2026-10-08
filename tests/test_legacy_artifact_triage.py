"""Synthetic-only, zero-network safety tests for legacy checkpoint triage."""
import contextlib
import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from triage_legacy_artifacts import canonical_host, classify, inspect_archive, load_existing_inventory, triage, write_private, combine_private_audits


class LegacyAuditTriageTests(unittest.TestCase):
    def test_safe_classification(self):
        self.assertEqual(classify("NO_GENERAL_FORM", False), (1, "EXTENDED_CONTACT_RECHECK"))
        self.assertEqual(classify("GET_US_DNS_ERROR", False), (6, "SAFE_NETWORK_RECHECK"))
        self.assertEqual(classify("GET_HTTP_503", False), (6, "SAFE_NETWORK_RECHECK"))
        self.assertEqual(classify("GET_HTTP_404", False), (5, "UNAVAILABLE_SITE_HUMAN_REVIEW"))
        self.assertEqual(classify("GET_US_THREAT_BLOCKED", False)[0], 99)
        self.assertEqual(classify("US_SOLICITATION_PROHIBITED", False)[0], 99)
        self.assertEqual(classify("SITE_FORM_ELIGIBLE_PRE_COMPLIANCE", True)[0], 99)
        self.assertEqual(classify("SITE_FORM_ELIGIBLE_PRE_COMPLIANCE", False),
                         (99, "ALREADY_PRECOMPLIANCE_CANDIDATE"))
        self.assertEqual(classify("TERMINAL_RETRY_EXHAUSTED_GET_HTTP_503", False)[0], 99)

    def test_bad_hosts_are_never_queued(self):
        for h in ["localhost", "192.168.0.1", "127.0.0.1", "bad.local", "foo..bar", "a_b.test", "10.0.0.2", "host.internal", "127.1", "0x7f.0x0.0x0.0x1"]:
            self.assertIsNone(canonical_host({"normalizedDomain": h}), h)
        self.assertEqual(canonical_host({"normalizedDomain": "WWW.STUDIO.EXAMPLE."}), "studio.example")

    def test_duplicate_and_confirmed_candidate_protection(self):
        rows = [
            {"release": "2026-09-23.1", "targetTier": "NEAR_CORE", "normalizedDomain": "www.studio.example", "status": "NO_GENERAL_FORM"},
            {"release": "2026-09-23.1", "targetTier": "NEAR_CORE", "normalizedDomain": "studio.example", "status": "WRONG_FORM_PURPOSE"},
            {"release": "2026-09-23.1", "targetTier": "NEAR_CORE", "normalizedDomain": "blocked.example", "status": "GET_US_THREAT_BLOCKED"},
            {"release": "2026-09-23.1", "targetTier": "NEAR_CORE", "normalizedDomain": "already.example", "status": "NO_GENERAL_FORM"},
        ]
        queue, counts, _, bad, duplicates = triage(rows, "NEAR_CORE", {"already.example"})
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["queue_kind"], "FORM_PURPOSE_REVIEW")
        self.assertEqual(queue[0]["https_origin"], "https://studio.example/")
        self.assertEqual(bad, 0)
        self.assertEqual(duplicates, 1)
        self.assertEqual(counts["EXPLICITLY_RESTRICTED_OR_TERMINAL"], 1)

    def test_read_only_archive_inputs(self):
        with tempfile.TemporaryDirectory(prefix="public-offline-fixture-") as td:
            a = Path(td) / "synthetic.zip"
            rows = [{"release": "2026-09-23.1", "targetTier": "NEAR_CORE", "normalizedDomain": "safe.example", "status": "NO_GENERAL_FORM"}]
            with zipfile.ZipFile(a, "w") as z:
                z.writestr("overture-us-near-core-full-audit-results.json", json.dumps(rows))
            data, tier, digest = inspect_archive(a)
            self.assertEqual(len(data), 1)
            self.assertEqual(tier, "NEAR_CORE")
            self.assertEqual(len(digest), 64)
            self.assertEqual(digest, hashlib.sha256(a.read_bytes()).hexdigest())

    def test_explicit_restrictions_veto_soft_audit_outcomes_in_both_row_orders(self):
        blockers = [
            ("GET_US_THREAT_BLOCKED", False),
            ("GET_US_PRIVATE_ADDRESS_BLOCKED", False),
            ("US_SOLICITATION_PROHIBITED", False),
            ("US_AUTOMATION_PROHIBITED", False),
            ("TERMINAL_RETRY_EXHAUSTED_GET_HTTP_503", False),
            ("GET_HTTP_403", False),
            ("SITE_FORM_ELIGIBLE_PRE_COMPLIANCE", True),
            ("GET_US_DNS_ERROR", True),
        ]
        for status, already_eligible in blockers:
            for reverse in (False, True):
                soft = {"release": "2026-09-23.1", "targetTier": "CORE",
                        "normalizedDomain": "www.someone.example", "status": "NO_GENERAL_FORM"}
                blocked = {"release": "2026-09-23.1", "targetTier": "CORE",
                           "normalizedDomain": "someone.example", "status": status,
                           "siteFormEligiblePreCompliance": already_eligible}
                rows = [blocked, soft] if reverse else [soft, blocked]
                queue, groups, _, _, duplicates = triage(rows, "CORE")
                self.assertEqual(queue, [], (status, reverse))
                self.assertEqual(duplicates, 1)
                self.assertEqual(sum(groups.values()), 1)

    def test_external_or_dynamic_form_is_manual_review_only(self):
        self.assertEqual(classify("CONTACT_CHANNEL_REVIEW", False),
                         (0, "CONTACT_CHANNEL_HUMAN_REVIEW"))
        rows = [{"release": "2026-09-23.1", "targetTier": "CORE",
                 "normalizedDomain": "channel.example", "status": "CONTACT_CHANNEL_REVIEW"}]
        queue, _, _, _, _ = triage(rows, "CORE")
        self.assertEqual(queue[0]["queue_kind"], "CONTACT_CHANNEL_HUMAN_REVIEW")
        self.assertNotIn("sendAuthorized", queue[0])

    def test_private_output_cannot_follow_symlinks_or_overwrite(self):
        with tempfile.TemporaryDirectory(prefix="audit-private-files-test-") as td:
            root = Path(td)
            victim = root / "victim.txt"
            victim.write_text("SAFE_ORIGINAL", encoding="utf-8")
            output = root / "PRIVATE_RECHECK_QUEUE.csv"
            output.symlink_to(victim)
            with self.assertRaises(OSError):
                write_private(output, "ATTACK")
            self.assertEqual(victim.read_text(), "SAFE_ORIGINAL")
            output.unlink()
            write_private(output, "first")
            with self.assertRaises(FileExistsError):
                write_private(output, "second")
            self.assertEqual(output.read_text(), "first")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_zip_archive_duplicate_result_file_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="audit-zip-double-entry-") as td:
            archive = Path(td) / "reused.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(archive, "w") as z:
                    for _ in range(2):
                        z.writestr("overture-us-core-full-audit-results.json", "[]")
            with self.assertRaisesRegex(ValueError, "DUPLICATE_AUDIT_ARCHIVE_MEMBER"):
                inspect_archive(archive)

    def test_cross_tier_threat_blocks_otherwise_recheckable_website(self):
        sha = lambda value: hashlib.sha256(value.encode()).hexdigest()
        archives = [
            ([{"release": "2026-09-23.1", "targetTier": "CORE",
               "normalizedDomain": "www.shared.example", "status": "NO_GENERAL_FORM"}],
             "CORE", sha("core")),
            ([{"release": "2026-09-23.1", "targetTier": "NEAR_CORE",
               "normalizedDomain": "shared.example", "status": "GET_US_THREAT_BLOCKED"}],
             "NEAR_CORE", sha("near")),
            ([{"release": "2026-09-23.1", "targetTier": "ADJACENT",
               "normalizedDomain": "unrelated.example", "status": "NEEDS_REVIEW"}],
             "ADJACENT", sha("adjacent"))
        ]
        for order in (archives, list(reversed(archives))):
            records, sources = combine_private_audits(order)
            queue, groups, _, invalid, duplicates = triage(records, "ALL")
            self.assertEqual(len(sources), 3)
            self.assertEqual(len(queue), 1)
            self.assertEqual(queue[0]["host"], "unrelated.example")
            self.assertEqual(queue[0]["tier"], "ADJACENT")
            self.assertEqual(groups["EXPLICITLY_RESTRICTED_OR_TERMINAL"], 1)
            self.assertEqual(invalid, 0)
            self.assertEqual(duplicates, 1)

    def test_cross_tier_dedupe_is_stable_and_retains_source_tier(self):
        sha = lambda value: hashlib.sha256(value.encode()).hexdigest()
        archives = [
            ([{"release": "2026-09-23.1", "normalizedDomain": "www.care.example",
               "status": "GET_US_TIMEOUT"}], "ADJACENT", sha("adjacent")),
            ([{"release": "2026-09-23.1", "normalizedDomain": "care.example",
               "status": "NO_GENERAL_FORM"}], "NEAR_CORE", sha("near")),
            ([{"release": "2026-09-23.1", "normalizedDomain": "already.example",
               "status": "NEEDS_REVIEW"}], "CORE", sha("core"))
        ]
        for order in (archives, list(reversed(archives))):
            records, _ = combine_private_audits(order)
            queue, *_ = triage(records, "ALL", {"already.example"})
            self.assertEqual(len(queue), 1)
            self.assertEqual(queue[0]["host"], "care.example")
            self.assertEqual(queue[0]["tier"], "NEAR_CORE")
            self.assertEqual(queue[0]["queue_kind"], "EXTENDED_CONTACT_RECHECK")

    def test_cross_tier_archive_input_rejects_conflicts_and_duplicates(self):
        sha = hashlib.sha256(b"fixture").hexdigest()
        with self.assertRaisesRegex(ValueError, "DUPLICATE_OR_INVALID_AUDIT_SOURCE"):
            combine_private_audits([([], "CORE", sha), ([], "NEAR_CORE", sha)])
        with self.assertRaisesRegex(ValueError, "TIER_CROSSING_AUDIT_RECORD"):
            combine_private_audits([
                ([{"targetTier": "CORE", "normalizedDomain": "safe.example"}],
                 "ADJACENT", sha)
            ])
        with self.assertRaisesRegex(ValueError, "AUDIT_ARCHIVE_COUNT_UNSUPPORTED"):
            combine_private_audits([])

    def test_private_inventory_archive_requires_exact_manifest_and_schema(self):
        with tempfile.TemporaryDirectory(prefix="inventory-sanity-fixture-") as td:
            path = Path(td) / "inventory.zip"
            name = "us-precompliance-inventory-export.csv"
            meta_name = "us-precompliance-inventory-export-manifest.json"
            data = b"normalized_domain\nwww.studio.example\n"
            manifest = {"csvSha256": hashlib.sha256(data).hexdigest(),
                        "uniqueDomains": 1, "release": "2026-09-23.1"}
            with zipfile.ZipFile(path, "w") as z:
                z.writestr(name, data)
                z.writestr(meta_name, json.dumps(manifest))
            hosts, digest = load_existing_inventory(path)
            self.assertEqual(hosts, {"studio.example"})
            self.assertEqual(digest, manifest["csvSha256"])
            manifest["uniqueDomains"] = 2
            with zipfile.ZipFile(path, "w") as z:
                z.writestr(name, data)
                z.writestr(meta_name, json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "INVENTORY_ROW_COUNT_MISMATCH"):
                load_existing_inventory(path)
            manifest["uniqueDomains"] = 1
            manifest["release"] = "../unauthorized"
            with zipfile.ZipFile(path, "w") as z:
                z.writestr(name, data)
                z.writestr(meta_name, json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "INVENTORY_MANIFEST_INVALID"):
                load_existing_inventory(path)

    def test_inventory_duplicate_zip_entry_refused(self):
        with tempfile.TemporaryDirectory(prefix="inventory-duplicate-") as td:
            p = Path(td) / "double.zip"
            name = "us-precompliance-inventory-export.csv"
            meta = "us-precompliance-inventory-export-manifest.json"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(p, "w") as z:
                    z.writestr(name, "normalized_domain\nexample.com\n")
                    z.writestr(name, "normalized_domain\nsecond.example\n")
                    z.writestr(meta, "{}")
            with self.assertRaisesRegex(ValueError, "INVENTORY_EXPORT_OR_MANIFEST_DUPLICATE_OR_MISSING"):
                load_existing_inventory(p)

    def test_inventory_declared_oversize_blocked_before_decompression(self):
        with tempfile.TemporaryDirectory(prefix="inventory-zipbomb-") as td:
            p = Path(td) / "large.zip"
            name = "us-precompliance-inventory-export.csv"
            meta = "us-precompliance-inventory-export-manifest.json"
            with zipfile.ZipFile(p, "w", compression=zipfile.ZIP_DEFLATED) as z:
                z.writestr(name, b"x" * (32 * 1024 * 1024 + 1))
                z.writestr(meta, "{}")
            with self.assertRaisesRegex(ValueError, "INVENTORY_ARCHIVE_SIZE_INVALID"):
                load_existing_inventory(p)

    def test_public_actions_must_not_process_legacy_private_data(self):
        with tempfile.TemporaryDirectory(prefix="public-offline-deny-") as td:
            p = Path(td) / "input.zip"
            p.write_bytes(b"this-does-not-matter; guard must abort before opening")
            out = Path(td) / "private"
            env = {**os.environ, "GITHUB_ACTIONS": "true"}
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / "triage_legacy_artifacts.py"),
                "--audit-zip", str(p), "--private-out", str(out)],
                env=env, capture_output=True, text=True, timeout=6)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("PUBLIC_GITHUB_ACTIONS_PRIVATE_DATA_PROCESSING_DENIED", result.stderr + result.stdout)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()