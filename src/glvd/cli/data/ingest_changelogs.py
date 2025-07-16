# SPDX-License-Identifier: MIT

from __future__ import annotations

import json
import asyncio
import logging
import os
from pathlib import Path
from sqlalchemy import select


from sqlalchemy.dialects.postgresql import insert

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from glvd.database import Base, CveContext, DebCve
from . import cli


logger = logging.getLogger(__name__)


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
            print(cve_contexts)

            result = await session.execute(
                select(DebCve).where(
                DebCve.debsec_vulnerable == True,
                DebCve.gardenlinux_version == str(self.gl_version)
                )
            )
            vulnerable_cves = result.scalars().all()
            print(vulnerable_cves)


if __name__ == "__main__":
    IngestChangelogs.run()
