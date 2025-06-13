import pytest
from sqlalchemy import select

from glvd.cli.data.combine_deb import CombineDeb


from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
)

from glvd.database import DebCve

@pytest.mark.asyncio
async def test_can_combine_deb():
    engine = create_async_engine('postgresql+asyncpg://glvd:glvd@localhost:5432/glvd', echo=True)

    async with async_sessionmaker(engine)() as session:
        result = await session.execute(select(DebCve))
        assert result.fetchall() == []

    await CombineDeb()(engine)

    async with async_sessionmaker(engine)() as session:
        result = await session.execute(select(DebCve))
        assert len(result.fetchall()) > 0
