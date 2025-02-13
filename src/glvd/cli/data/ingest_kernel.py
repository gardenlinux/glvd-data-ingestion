# SPDX-License-Identifier: MIT

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from glvd.database import Base
from . import cli


logger = logging.getLogger(__name__)


class IngestKernel:
    @staticmethod
    @cli.register(
        'ingest-kernel',
        arguments=[
            cli.prepare_argument(
                'dir',
                help='data directory out of https://git.kernel.org/pub/scm/linux/security/vulns.git',
                metavar='KERNEL_VULNS',
                type=Path,
            ),
        ]
    )
    def run(*, argparser: None, dir: Path, database: str, debug: bool) -> None:
        logging.basicConfig(level=debug and logging.DEBUG or logging.INFO)
        engine = create_async_engine(database, echo=debug)
        asyncio.run(IngestKernel(dir)(engine))

    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> any:
        # Implement the logic to read the kernel CVEs from the given path
        pass

    async def import_file(
        self,
        session: AsyncSession,
    ) -> None:
        file_cve = self.read()
        # Implement the logic to process the file_cve

    async def __call__(
        self,
        engine: AsyncEngine,
    ) -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async with async_sessionmaker(engine)() as session:
            await self.import_file(session)
            await session.commit()


if __name__ == '__main__':
    IngestKernel.run()
