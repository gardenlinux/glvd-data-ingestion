# SPDX-License-Identifier: MIT

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from sqlalchemy import select
import re
import requests
import lzma
import tarfile
import io
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


logger = logging.getLogger("ingest_changelogs")


def parse_debian_apt_source_index_file(file_path):
    logger.info(f"Parsing Debian APT source index file: {file_path}")
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        logger.error(f"Failed to read file {file_path}: {e}")
        raise

    entries = re.split(r'\n\s*\n', content.strip())
    results = []

    for entry in entries:
        lines = entry.strip().split('\n')
        format_ = None
        directory = None
        files = []
        in_files_section = False

        for line in lines:
            if line.startswith('Format:'):
                format_ = line.split(':', 1)[1].strip()
            elif line.startswith('Directory:'):
                directory = line.split(':', 1)[1].strip()
            elif line.startswith('Package:'):
                package = line.split(':', 1)[1].strip()
            elif line.startswith('Files:'):
                in_files_section = True
            elif in_files_section:
                if line.strip() == '':
                    continue
                if line.startswith(' ') or line.startswith('\t'):
                    files.append(line.strip())
                else:
                    in_files_section = False

        # We have special handling for the kernel because we don't use debian's build for that
        if package != 'linux':
            results.append({
                'Format': format_,
                'Directory': directory,
                'Files': files,
                'Package': package
            })

    logger.info(f"Parsed {len(results)} entries from source index file")
    return results

def add_cve_entry(resolved_cves, cve_id, package_name, changelog_text):
    logger.info(f"Adding CVE entry: {cve_id} for package {package_name}")
    if cve_id not in resolved_cves:
        resolved_cves[cve_id] = {}
    if package_name not in resolved_cves[cve_id]:
        resolved_cves[cve_id][package_name] = []
    resolved_cves[cve_id][package_name].append(changelog_text)



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
            logger.info(f"Loaded CVE contexts for Garden Linux {self.gl_version}: {cve_contexts}")

            result = await session.execute(
                select(DebCve).where(
                DebCve.debsec_vulnerable == True,
                DebCve.gardenlinux_version == str(self.gl_version)
                )
            )
            vulnerable_cves = result.scalars().all()
            logger.info(f"Vulnerable CVEs for Garden Linux {self.gl_version}: {vulnerable_cves}")
            cve_ids = [cve.cve_id for cve in vulnerable_cves]
            logger.info(f"Vulnerable CVE IDs for Garden Linux {self.gl_version}: {cve_ids}")

            # Only act on CVEs that don't have context yet
            # Maybe this condition should be refined, for example to only match those where the status is set to 'resolved'
            existing_cve_ids = {ctx.cve_id for ctx in cve_contexts}
            cve_ids = [cve_id for cve_id in cve_ids if cve_id not in existing_cve_ids]

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

            sources_path = f"/usr/local/src/data/ingest-debsrc/gardenlinux/lists/packages.gardenlinux.io_gardenlinux_dists_{self.gl_version}_main_source_Sources"
            logger.info(f"Using apt sources file from {sources_path}")

            parsed_entries = parse_debian_apt_source_index_file(sources_path)
            logger.info(f"Found {len(parsed_entries)} entries in source index file")

            resolved_cves = {}

            for entry in parsed_entries:
                logger.info(f"Processing entry: {entry.get('Package', 'unknown')}")
                if entry['Format'] == "3.0 (quilt)":
                    debian_tar_xz_file = next((f.split(' ')[2] for f in entry['Files'] if f.endswith('debian.tar.xz')), '')
                    if debian_tar_xz_file != '':
                        url = f"https://packages.gardenlinux.io/gardenlinux/{entry['Directory']}/{debian_tar_xz_file}"
                        logger.info(f"Downloading debian.tar.xz from {url}")
                        try:
                            response = requests.get(url)
                            response.raise_for_status()
                        except Exception as e:
                            logger.error(f"Failed to download {url}: {e}")
                            continue

                        try:
                            decompressed = lzma.decompress(response.content)
                        except Exception as e:
                            logger.error(f"Failed to decompress xz file for {entry['Package']}: {e}")
                            continue

                        try:
                            with tarfile.open(fileobj=io.BytesIO(decompressed)) as tar:
                                changelog_member = tar.getmember("debian/changelog")
                                changelog_file = tar.extractfile(changelog_member)
                                changelog_content = changelog_file.read().decode("utf-8")
                                cl = changelog.Changelog(changelog_content)
                                for changelog_entry in cl:
                                    for change in changelog_entry.changes():
                                        for cve in vulnerable_cves:
                                            cve = str.strip(cve.cve_id)
                                            if cve in change:
                                                add_cve_entry(resolved_cves, cve, entry['Package'], f"Automated triage based on changelog from package {changelog_entry.package} at {changelog_entry.date} in version {changelog_entry.version}:\n{change}")
                        except Exception as e:
                            logger.error(f"Failed to extract or parse changelog for {entry['Package']}: {e}")
                            continue
                elif entry['Format'] == "3.0 (native)":
                    logger.info(f"Skipping native format for {entry.get('Package', 'unknown')}")
                    pass
                elif entry['Format'] == "1.0":
                    logger.info(f"Skipping format 1.0 for {entry.get('Package', 'unknown')}")
                    pass

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
