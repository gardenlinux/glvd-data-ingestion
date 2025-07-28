# SPDX-License-Identifier: MIT

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from sqlalchemy import select
import os
from debian import changelog

from sqlalchemy.dialects.postgresql import insert

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    async_sessionmaker,
    create_async_engine,
)

from glvd.database import CveContext, DebCve, DistCpe
from . import cli
import sys
import hashlib
import json


logger = logging.getLogger("ingest_changelogs")
cache_path = "/changelogs/cache.json"


def add_cve_entry(resolved_cves, cve_id, package_name, changelog_text):
    logger.info(f"Adding CVE entry: {cve_id} for package {package_name}")
    if cve_id not in resolved_cves:
        resolved_cves[cve_id] = {}
    if package_name not in resolved_cves[cve_id]:
        resolved_cves[cve_id][package_name] = []
    resolved_cves[cve_id][package_name].append(changelog_text)

def traverse_and_parse_changelogs(base_dir, gl_version):
    results = []
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith("_changelog.txt"):
                filepath = os.path.join(root, file)
                results.append({
                    "gardenlinux_version": gl_version,
                    "filename": file,
                    "filepath": filepath,
                })
    return results


class IngestChangelogs:
    @staticmethod
    @cli.register(
        "ingest-changelogs",
        arguments=[
            cli.prepare_argument(
                "gl_version",
                help="Garden Linux version to ingest",
            ),
        ],
    )
    def run(*, argparser: None, gl_version: str, database: str, debug: bool) -> None:
        logging.basicConfig(level=debug and logging.DEBUG or logging.INFO)
        engine = create_async_engine(database, echo=debug)
        asyncio.run(IngestChangelogs(gl_version)(engine))

    def __init__(self, gl_version: Path) -> None:
        self.gl_version = gl_version

    async def __call__(
        self,
        engine: AsyncEngine,
    ) -> None:
        async with async_sessionmaker(engine)() as session:
            logger.info(f"Ingesting Changelogs for Garden Linux {self.gl_version}")
            result = await session.execute(
                select(CveContext).where(CveContext.gardenlinux_version == str(self.gl_version))
            )
            cve_contexts = result.scalars().all()
            logger.info(f"Number of loaded CVE contexts for Garden Linux {self.gl_version}: {len(cve_contexts)}")

            result = await session.execute(
                select(DebCve).where(
                DebCve.debsec_vulnerable == True,
                DebCve.gardenlinux_version == str(self.gl_version)
                )
            )
            vulnerable_cves = result.scalars().all()
            cve_ids = [cve.cve_id for cve in vulnerable_cves]
            logger.info(f"Have {len(cve_ids)} CVEs for Garden Linux {self.gl_version}")

            # Only act on CVEs that don't have context yet
            # Maybe this condition should be refined, for example to only match those where the status is set to 'resolved'
            existing_cve_ids = {ctx.cve_id for ctx in cve_contexts}
            cve_ids = [cve_id for cve_id in cve_ids if cve_id not in existing_cve_ids]
            logger.info(f"Processing {len(cve_ids)} CVEs without triage information for Garden Linux {self.gl_version}")

            seen_changelogs = {}
            if os.path.exists(cache_path):
                try:
                    with open(cache_path, "r") as cache_file:
                        seen_changelogs = json.load(cache_file)
                    logger.info(f"Loaded seen_changelogs cache from {cache_path}")
                except Exception as e:
                    logger.error(f"Failed to load seen_changelogs cache: {e}")

            dist_id = None
            result = await session.execute(
                select(DistCpe.id).where(
                    DistCpe.cpe_product == "gardenlinux",
                    DistCpe.cpe_version == str(self.gl_version)
                )
            )
            dist_id_row = result.first()
            if dist_id_row:
                dist_id = dist_id_row[0]
                logger.info(f"Resolved Garden Linux version {self.gl_version} to dist id {dist_id}")
            else:
                logger.error(f"No dist_id found for Garden Linux version {self.gl_version}")
                sys.exit(1)

            resolved_cves = {}

            base_dir = f"/changelogs/{self.gl_version}"
            if not os.path.isdir(base_dir):
                logger.error(f"Changelog directory does not exist: {base_dir}")
                sys.exit(0)
            parsed = traverse_and_parse_changelogs(base_dir, self.gl_version)
            for entry in parsed:
                logger.info(f"Garden Linux version: {entry['gardenlinux_version']}, File: {entry['filename']}")

                with open(entry['filepath'], 'r') as f:
                    content = f.read()
                    sha256 = hashlib.sha256(content.encode('utf-8')).hexdigest()
                    logger.info(f"SHA256 of {entry['filename']}: {sha256}")

                    if seen_changelogs.get(sha256):
                        logger.info(
                            f"We have {len(seen_changelogs.get(sha256))} cached entries for {entry['filename']} with sha256 {sha256}"
                        )
                        for cached_entry in seen_changelogs.get(sha256):
                            add_cve_entry(resolved_cves, cached_entry['cve'], cached_entry['package'], cached_entry['message'])
                    else:
                        cl = changelog.Changelog(content)
                        for changelog_entry in cl:
                            for change in changelog_entry.changes():
                                for cve in cve_ids:
                                    if cve in change:
                                        add_cve_entry(resolved_cves, cve, cl.package, f"Automated triage based on changelog from package {changelog_entry.package} at {changelog_entry.date} in version {changelog_entry.version}:\n{change}")
                                        if not seen_changelogs.get(sha256):
                                            seen_changelogs[sha256] = []
                                        seen_changelogs[sha256].append(
                                            {
                                                "cve": cve,
                                                "package": cl.package,
                                                "message": f"Automated triage based on changelog from package {changelog_entry.package} at {changelog_entry.date} in version {changelog_entry.version}:\n{change}",
                                            }
                                        )

            try:
                # Convert keys to strings for JSON serialization
                serializable_seen_changelogs = {str(k): v for k, v in seen_changelogs.items()}
                with open(cache_path, "w") as cache_file:
                    json.dump(serializable_seen_changelogs, cache_file, indent=2)
                logger.info(f"Written seen_changelogs cache to {cache_path}")
            except Exception as e:
                logger.error(f"Failed to write seen_changelogs cache: {e}")

            # insert all values in resolved_cves into CveContext table
            for cve_id, package_dict in resolved_cves.items():
                for package_name, changelog_texts in package_dict.items():
                    for changelog_text in changelog_texts:
                        logger.info(f"Inserting CVE context: cve_id={cve_id}, package={package_name}, version={self.gl_version}, dist_id={dist_id}")
                        stmt = insert(CveContext).values(
                            cve_id=cve_id,
                            description=changelog_text,
                            gardenlinux_version=str(self.gl_version),
                            dist_id=dist_id,
                            use_case='all',
                            is_resolved=True,
                        ).on_conflict_do_nothing()
                        await session.execute(stmt)
            await session.commit()


if __name__ == "__main__":
    IngestChangelogs.run()
