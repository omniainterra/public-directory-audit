"""Public Overture directory discovery. This module never opens candidate websites.

Output is plaintext in an ephemeral GitHub-hosted runner workspace only. The workflow
must encrypt it and MUST NOT upload this intermediate file as a public artifact.
"""
import argparse
import json
import re
import sys
from urllib.parse import urlparse
from urllib.request import Request, urlopen

REGIONS = {
    "sf": (-123.0, 37.25, -122.30, 37.90, "CA"),
    "nyc": (-74.20, 40.56, -73.70, 40.92, "NY"),
    "boston": (-71.24, 42.23, -70.90, 42.45, "MA"),
    "miami": (-80.32, 25.66, -80.10, 25.86, "FL"),
    "raleigh": (-78.86, 35.66, -78.49, 35.95, "NC"),
    "seattle": (-122.47, 47.47, -122.20, 47.75, "WA"),
}
CATEGORIES = (
    "psychic_advising", "astrological_advising", "spiritual_advising", "reiki",
    "feng_shui", "life_coach", "yoga_studio", "meditation_center",
    "naturopathic_medicine", "complementary_and_alternative_medicine",
    "aromatherapy", "reflexology", "health_and_wellness_club",
)


def safe_public_website(raw):
    if not isinstance(raw, str) or len(raw) > 1800:
        return None
    try:
        parsed = urlparse(raw.strip())
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return None
        if parsed.username or parsed.password or parsed.port:
            return None
        host = parsed.hostname.lower().removeprefix("www.")
        if "." not in host or any(x in host for x in ("localhost", ".local", ".internal")):
            return None
        return host
    except ValueError:
        return None


def normalize_result(row, state):
    name = str(row[1] or "").strip()[:160]
    website = str(row[2] or "").strip()
    host = safe_public_website(website)
    if not host or not name:
        return None
    return {
        "id": str(row[0])[:100],
        "name": name,
        "url": website,
        "state": state,
        "category": str(row[3] or "")[:100],
        "source": "OVERTURE_PUBLIC",
        "host": host,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--area", choices=REGIONS, required=True)
    parser.add_argument("--limit", type=int, choices=(10, 20, 25), required=True)
    parser.add_argument("--out", default="candidates.jsonl")
    args = parser.parse_args()
    if args.out != "candidates.jsonl":
        parser.error("output must remain an ignored temporary file")
    try:
        import duckdb  # noqa: PLC0415
    except ImportError as exc:
        raise SystemExit("Pinned duckdb package is required") from exc

    request = Request("https://stac.overturemaps.org/catalog.json", headers={"Accept": "application/json"})
    with urlopen(request, timeout=20) as response:
        catalog = json.load(response)
    release = str(catalog.get("latest", ""))
    if not re.fullmatch(r"20\d{2}-\d{2}-\d{2}\.\d+", release):
        raise ValueError("OVERTURE_RELEASE_INVALID")
    west, south, east, north, state = REGIONS[args.area]
    source = f"s3://overturemaps-us-west-2/release/{release}/theme=places/type=place/*"
    connection = duckdb.connect(database=":memory:")
    connection.execute("INSTALL httpfs; LOAD httpfs;")
    connection.execute("SET s3_region='us-west-2';")
    connection.execute("SET s3_anonymous=true;")
    query = """
        SELECT CAST(id AS VARCHAR), names.primary, websites[1], taxonomy.primary
        FROM read_parquet(?, hive_partitioning=1)
        WHERE addresses[1].country='US'
          AND upper(addresses[1].region)=?
          AND bbox.xmin BETWEEN ? AND ?
          AND bbox.ymin BETWEEN ? AND ?
          AND websites[1] IS NOT NULL
          AND regexp_matches(websites[1], '^https?://')
          AND taxonomy.primary IN (SELECT unnest(?::VARCHAR[]))
          AND (operating_status IS NULL OR operating_status <> 'permanently_closed')
        LIMIT ?
    """
    # Overfetch by a small factor, then dedupe per registrable/normalized website hostname.
    rows = connection.execute(query, [source, state, west, east, south, north, list(CATEGORIES), args.limit * 8]).fetchall()
    hosts = set()
    selected = []
    for row in rows:
        candidate = normalize_result(row, state)
        if not candidate or candidate["host"] in hosts:
            continue
        hosts.add(candidate["host"])
        del candidate["host"]
        selected.append(candidate)
        if len(selected) >= args.limit:
            break
    if not selected:
        raise RuntimeError("NO_PUBLIC_CANDIDATES_FOUND")
    with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
        for record in selected:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    # Never print business names, URLs, contacts, or Overture identifiers to PUBLIC logs.
    print(json.dumps({"event": "PUBLIC_OVERTURE_DISCOVERY", "area": args.area,
                      "release": release, "candidates": len(selected), "exposedData": False}))


if __name__ == "__main__":
    main()
