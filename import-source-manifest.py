#!/usr/bin/env python3
import os
import sys
from pathlib import Path
import psycopg2
import argparse

def read_manifest(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        lines = [ln.strip() for ln in fh.readlines()]
    pkgs = sorted(lines)
    return pkgs

def main():
    parser = argparse.ArgumentParser(description="Import source manifest files into the database.")
    parser.add_argument(
        "--manifest-dir",
        type=Path,
        required=True,
        help="Directory containing manifest files",
    )
    parser.add_argument(
        "--suffix",
        type=str,
        default=".sourcemanifest",
        help="Suffix of manifest files",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be imported without writing to the database",
    )
    args = parser.parse_args()

    MANIFEST_DIR = args.manifest_dir
    SUFFIX = args.suffix
    DRY_RUN = args.dry_run
    DEFAULT_DB_URL_ENV = "DATABASE_URL"

    if not MANIFEST_DIR.is_dir():
        print(f"Manifest dir not found: {MANIFEST_DIR}", file=sys.stderr)
        sys.exit(1)

    files = sorted(MANIFEST_DIR.glob(f"*{SUFFIX}"))
    if not files:
        print("No manifest files found", file=sys.stderr)
        sys.exit(0)

    if DRY_RUN:
        for f in files:
            name = f.name.rsplit(SUFFIX, 1)[0]
            pkgs = read_manifest(f)
            print(f"[DRY RUN] Would import {len(pkgs)} packages for image '{name}': {pkgs}")
        return

    database_url = os.environ.get(DEFAULT_DB_URL_ENV)
    if not database_url:
        print(f"{DEFAULT_DB_URL_ENV} must be set", file=sys.stderr)
        sys.exit(1)

    conn = psycopg2.connect(database_url)
    try:
        with conn:
            with conn.cursor() as cur:
                for f in files:
                    name = f.name.rsplit(SUFFIX, 1)[0]
                    pkgs = read_manifest(f)
                    # Upsert into image_variant (cname, source_packages)
                    cur.execute(
                        """
                        INSERT INTO image_variant (cname, source_packages)
                        VALUES (%s, %s)
                        ON CONFLICT (cname)
                        DO UPDATE SET source_packages = EXCLUDED.source_packages
                        """,
                        (name, pkgs),
                    )
                    print(f"Imported {len(pkgs)} packages for image '{name}'")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
