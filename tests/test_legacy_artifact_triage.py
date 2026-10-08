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
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from triage_legacy_artifacts import canonical_host, classify, inspect_archive, load_existing_inventory, triage


class LegacyAuditTriageTests(unittest.TestCase):
    def test_safe_classification(self):
        self.assertEqual(classify("NO_GENERAL_FORM", False), (1, "EXTENDED_CONTACT_RECHECK"))
        self.assertEqual(classify("GET_US_DNS_ERROR", False), (6, "SAFE_NETWORK_RECHECK"))
        self.assertEqual(classify("GET_HTTP_503", False), (6, "SAFE_NETWORK_RECHECK"))
        self.assertEqual(classify("GET_HTTP_404", False), (5, "UNAVAILABLE_SITE_HUMAN_REVIEW"))
        self.assertEqual(classify("GET_US_THREAT_BLOCKED", False)[0], 99)
        self.assertEqual(classify("US_SOLICITATION_PROHIBITED", False)[0], 99)
        self.assertEqual(classify("SITE_FORM_ELIGIBLE_PRE_COMPLIANCE", True)[0], 99)
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