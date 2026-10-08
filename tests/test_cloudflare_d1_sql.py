"""Offline SQLite verification of the atomic SQL used by the Cloudflare D1 gateway."""
import json
import sqlite3
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
LOAD_SQL = ('import {RESERVE_SQL,STORE_SQL} from "./src/cloudflare-private-ledger.mjs";'
            'process.stdout.write(JSON.stringify({RESERVE_SQL,STORE_SQL}));')
def statements():
    source = subprocess.check_output(
        ["node", "--input-type=module", "-e", LOAD_SQL],
        cwd=ROOT, text=True, timeout=10
    )
    return json.loads(source)
def connection(database=":memory:"):
    con = sqlite3.connect(database, timeout=10, isolation_level=None)
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript((ROOT / "migrations/0001_private_ledger.sql").read_text())
    return con

class D1LedgerSqlTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.queries = statements()

    def test_daily_cap_is_atomic_and_duplicate_does_not_consume_slot(self):
        con = connection()
        sql = self.queries["RESERVE_SQL"]
        day = "2026-10-08"
        ids = [str(uuid4()) for _ in range(4)]
        for i in range(2):
            row = con.execute(sql, (ids[i], day, day+"T10:00:00Z", day, 2, ids[i])).fetchone()
            self.assertEqual(row, (ids[i],))
        duplicate = con.execute(sql, (ids[0], day, day+"T10:00:00Z", day, 2, ids[0])).fetchone()
        self.assertIsNone(duplicate)
        overflow = con.execute(sql, (ids[2], day, day+"T10:00:00Z", day, 2, ids[2])).fetchone()
        self.assertIsNone(overflow)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM audit_reservations").fetchone()[0], 2)
        other = con.execute(sql, (ids[3], "2026-10-09", day+"T11:00:00Z", "2026-10-09", 2, ids[3])).fetchone()
        self.assertEqual(other, (ids[3],))
        con.close()

    def test_encrypted_report_requires_existing_reservation_and_is_immutable(self):
        con = connection()
        reserve = self.queries["RESERVE_SQL"]
        store = self.queries["STORE_SQL"]
        day = "2026-10-08"
        i = str(uuid4())
        other = str(uuid4())
        fake_ciphertext = '{"ciphertext":"ONLY_ENCRYPTED","version":1}'
        missing = con.execute(store, (other, fake_ciphertext, "a"*64, day+"T10:00:00Z", other)).fetchone()
        self.assertIsNone(missing)
        con.execute(reserve, (i,day,day+"T10:00:00Z",day,2,i)).fetchone()
        result = con.execute(store, (i,fake_ciphertext,"a"*64,day+"T10:00:00Z",i)).fetchone()
        self.assertEqual(result,(i,))
        retry = con.execute(store,(i,"OVERWRITE","b"*64,day+"T10:05:00Z",i)).fetchone()
        self.assertIsNone(retry)
        self.assertEqual(con.execute("SELECT payload_json FROM encrypted_reports WHERE request_id=?",(i,)).fetchone()[0],fake_ciphertext)
        columns = [r[1] for r in con.execute("PRAGMA table_info(encrypted_reports)")]
        for forbidden in ("website","customer_name","email","url","plaintext","form_url"):
            self.assertNotIn(forbidden, columns)
        con.close()

    def test_storage_byte_cap_and_foreign_key(self):
        con = connection()
        i = str(uuid4())
        with self.assertRaises(sqlite3.IntegrityError):
            con.execute("INSERT INTO encrypted_reports(request_id,day_utc,payload_json,payload_sha256,created_at_utc) VALUES (?,?,?,?,?)",
                        (i,"2026-10-08","a","b"*64,"2026-10-08T00:00:00Z"))
        with self.assertRaises(sqlite3.IntegrityError):
            con.execute("INSERT INTO audit_reservations(request_id,day_utc,created_at_utc) VALUES (?,?,?)",
                        (i,"2026-10-08","a"*35))
        con.close()

    def test_competing_requests_respect_per_day_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            filename=str(Path(directory)/"ledger.sqlite")
            con=connection(filename)
            con.execute("PRAGMA journal_mode=WAL")
            con.close()
            sql=self.queries["RESERVE_SQL"]
            day="2026-10-08"
            def contender(_):
                local=sqlite3.connect(filename,timeout=10,isolation_level=None)
                ident=str(uuid4())
                try:
                    return bool(local.execute(sql,(ident,day,day+"T10:00:00Z",day,3,ident)).fetchone())
                finally:
                    local.close()
            with ThreadPoolExecutor(max_workers=8) as pool:
                successful=list(pool.map(contender, range(12)))
            self.assertEqual(sum(successful),3)
            con=connection(filename)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM audit_reservations").fetchone()[0],3)
            con.close()

if __name__ == "__main__":
    unittest.main()
