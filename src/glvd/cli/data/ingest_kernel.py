# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import asyncio
import logging
import os
from pathlib import Path

from sqlalchemy.dialects.postgresql import insert

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from glvd.database import Base, CveContextKernel
from . import cli


logger = logging.getLogger(__name__)


# LTS kernel versions to check.
# This needs to be updated once we support a new kernel version, or drop support for one.
# fixme(fwilhe): Get rid of the need for manual maintenance.
lts_versions = ["6.6", "6.12"]

# List of irrelevant kernel subsystems in the context of Garden Linux.
# We still record CVEs related to those subsystems, but we'll focus less on them.
irrelevant_subsystems = [
    "afs",
    "xen",
    "x86/hyperv",
    "wifi",
    "video/",
    "staging",
    "drm",
    "can",
    "Bluetooth",
    "mmc",
    "nfc",
    "thunderbolt",
    "s390",
    "riscv",
    "powerpc",
    "nouveau",
    "media",
    "leds",
    "usb",
    "MIPS",
    "nilfs2",
    "ubifs",
    "ocfs2",
    "spi",
    "i3c",
    "um",
    "udf",
    "atm",
    "eventfs",
    "fs/9p",
    "gtp",
    "hid",
    "i2c",
    "ice",
    "hwmon",
    "mailbox",
    "misc",
    "f2fs",
    "libfs",
    "dma-buf",
    "binder",
    "alsa",
    "dev/parport",
    "closures",
    "devres",
    "fs/ntfs3",
    "hfs",
    "hfsplus",
    "ibmvnic",
    "iio",
    "jfs",
    "misdn",
    "padata",
    "pds_core",
    "parisc",
    "loongarch",
]


def compare_versions(v1: str, v2: str) -> int:
    v1_parts = list(map(int, v1.split(".")))
    v2_parts = list(map(int, v2.split(".")))

    # Compare each part of the version
    for v1_part, v2_part in zip(v1_parts, v2_parts):
        if v1_part < v2_part:
            return -1
        elif v1_part > v2_part:
            return 1

    # If all parts are equal, compare the length of the version parts
    if len(v1_parts) < len(v2_parts):
        return -1
    elif len(v1_parts) > len(v2_parts):
        return 1
    return 0


def is_relevant_subsystem(program_files: list[str]) -> bool:
    for file in program_files:
        for submodule in irrelevant_subsystems:
            if submodule in file:
                return False
    return True


def get_fixed_versions(
    lts_versions: list[str], cve_data: dict
) -> dict[str, str | None]:
    fixed_versions = dict.fromkeys(lts_versions, None)

    for entry in cve_data["containers"]["cna"]["affected"]:
        if "versions" not in entry:
            logging.debug(f"No 'versions' key in entry: {entry}")
            continue

        for ver in entry["versions"]:
            version: str = ver["version"]
            if ver["status"] == "unaffected":
                for lts in lts_versions:
                    if version.startswith(lts):
                        if (
                            fixed_versions[lts] is None
                            or compare_versions(version, fixed_versions[lts]) < 0
                        ):
                            logging.debug(
                                f"Updating fixed version for {lts}: {fixed_versions[lts]} -> {version}"
                            )
                            fixed_versions[lts] = version
                        else:
                            logging.debug(
                                f"Skipping version {version} for {lts} as it is not earlier than {fixed_versions[lts]}"
                            )
            else:
                logging.debug(f"Version {version} is affected, skipping")
    return fixed_versions


class IngestKernel:
    @staticmethod
    @cli.register(
        "ingest-kernel",
        arguments=[
            cli.prepare_argument(
                "dir",
                help="data directory out of https://git.kernel.org/pub/scm/linux/security/vulns.git",
                metavar="KERNEL_VULNS",
                type=Path,
            ),
        ],
    )
    def run(*, argparser: None, dir: Path, database: str, debug: bool) -> None:
        logging.basicConfig(level=debug and logging.DEBUG or logging.INFO)
        engine = create_async_engine(database, echo=debug)
        asyncio.run(IngestKernel(dir)(engine))

    def __init__(self, path: Path) -> None:
        self.path = path

    def iterate_kernel_cve_json_files(self) -> list[Path]:
        cve_files = []
        for file_path in self.path.glob("**/*.json"):
            if file_path.is_file():
                cve_files.append(file_path)
        return cve_files

    async def import_file(
        self,
        filepath,
        session: AsyncSession,
    ) -> None:
        logging.debug(f"Processing file: {filepath}")

        # Save the file contents to put it into the db.
        # As of now, we don't have a need for this, but it might be useful later.
        contents = ""
        with open(filepath, "r") as file:
            cve_data = json.load(file)
            contents = json.dumps(cve_data)

        # Determine if the CVE affects a relevant module in the context of Garden Linux
        program_files = []
        for entry in cve_data["containers"]["cna"]["affected"]:
            program_files.extend(entry.get("programFiles", []))
        relevant_subsystem = is_relevant_subsystem(program_files)

        # Get fixed versions for the specified LTS kernels
        fixed_versions = get_fixed_versions(lts_versions, cve_data)

        # Insert the results into the database
        cve_id = os.path.basename(filepath).replace(".json", "")

        logger.info(f"{cve_id} is fixed in {fixed_versions}")

        for lts, version in fixed_versions.items():
            is_fixed = version is not None

            await session.execute(
                insert(CveContextKernel)
                .values(
                    cve_id=cve_id,
                    lts_version=lts,
                    fixed_version=version,
                    is_fixed=is_fixed,
                    is_relevant_subsystem=relevant_subsystem,
                    source_data=contents,
                )
                .on_conflict_do_update(
                    index_elements=["cve_id", "lts_version"],
                    set_={
                        "fixed_version": version,
                        "is_fixed": is_fixed,
                        "is_relevant_subsystem": relevant_subsystem,
                        "source_data": contents,
                    },
                )
            )

    async def __call__(
        self,
        engine: AsyncEngine,
    ) -> None:
        async with async_sessionmaker(engine)() as session:
            files = self.iterate_kernel_cve_json_files()

            for f in files:
                await self.import_file(f, session)
            await session.commit()


if __name__ == "__main__":
    IngestKernel.run()
