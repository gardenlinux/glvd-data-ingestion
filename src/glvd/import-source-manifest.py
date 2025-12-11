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


def parse_name_version(filename: str, suffix: str):
    # Remove the suffix
    base = filename.rsplit(suffix, 1)[0]
    # Split by '-' from the right: ...-today-local
    parts = base.rsplit("-", 2)
    if len(parts) != 3:
        raise ValueError(f"Filename '{filename}' does not match expected pattern")
    name, version, commit_id = parts
    # Remove the architecture (rightmost element after last '-') from name
    name_parts = name.rsplit("-", 1)
    if len(name_parts) == 2:
        name = name_parts[0]
    return name, version, commit_id


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
            try:
                image_name, image_version, commit_id = parse_name_version(
                    f.name, SUFFIX
                )
            except ValueError as e:
                print(f"[DRY RUN] Skipping {f.name}: {e}")
                continue
            pkgs = read_manifest(f)
            print(
                f"[DRY RUN] Would import {len(pkgs)} packages for image '{image_name}', version '{image_version}': {pkgs}"
            )
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
                    try:
                        image_name, image_version, commit_id = parse_name_version(
                            f.name, SUFFIX
                        )
                    except ValueError as e:
                        print(f"Skipping {f.name}: {e}", file=sys.stderr)
                        continue
                    pkgs = read_manifest(f)

                    # Upsert into image_variant (image_name, image_version, commit_id)
                    cur.execute(
                        """
                        INSERT INTO image_variant (namespace, image_name, image_version, commit_id, packages)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (namespace, image_name, image_version)
                        DO UPDATE SET
                            commit_id = EXCLUDED.commit_id,
                            packages = EXCLUDED.packages
                        RETURNING id
                        """,
                        ("gardenlinux", image_name, image_version, commit_id, pkgs),
                    )
                    image_variant_id = cur.fetchone()[0]

                    # Remove existing packages for this image_variant_id
                    cur.execute(
                        "DELETE FROM image_package WHERE image_variant_id = %s",
                        (image_variant_id,),
                    )
                    # Insert new packages
                    for pkg in pkgs:
                        cur.execute(
                            "INSERT INTO image_package (image_variant_id, package_name) VALUES (%s, %s)",
                            (image_variant_id, pkg),
                        )
                    print(
                        f"Imported {len(pkgs)} packages for image '{image_name}', version '{image_version}'"
                    )
    finally:
        conn.close()

if __name__ == "__main__":
    main()
