# SPDX-License-Identifier: MIT

from __future__ import annotations

from datetime import datetime
from typing import (
    Any,
    Optional,
    Self,
)

from sqlalchemy import (
    ForeignKey,
    Identity,
    Index,
    Column,
    Boolean,
    Integer,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    MappedAsDataclass,
    mapped_column,
    relationship,
)
from sqlalchemy.sql import func
from sqlalchemy.types import (
    DateTime,
    JSON,
    Text,
)

from sqlalchemy.dialects.postgresql import JSONB

from ..data.cvss import CvssSeverity
from .types import (
    CvssSeverityType,
    DebVersion,
)


class Base(MappedAsDataclass, DeclarativeBase):
    type_annotation_map = {
        str: Text,
        datetime: DateTime(timezone=True),
        Any: JSON,
        CvssSeverity: CvssSeverityType,
    }


class NvdCve(Base):
    __tablename__ = 'nvd_cve'

    cve_id: Mapped[str] = mapped_column(primary_key=True)
    last_mod: Mapped[datetime]
    data: Mapped[Any]


class DistCpe(Base):
    __tablename__ = 'dist_cpe'

    id = Column(
        "id", Integer, Identity(start=1), primary_key=True
    )
    cpe_vendor: Mapped[str]
    cpe_product: Mapped[str]
    cpe_version: Mapped[str]
    deb_codename: Mapped[str]


class Debsrc(Base):
    __tablename__ = 'debsrc'

    dist_id = mapped_column(ForeignKey(DistCpe.id), primary_key=True)
    gardenlinux_version = Column(Text)
    last_mod: Mapped[datetime] = mapped_column(init=False, server_default=func.now(), onupdate=func.now())
    deb_source: Mapped[str] = mapped_column(primary_key=True)
    deb_version: Mapped[str] = mapped_column(DebVersion)
    minor_deb_version: Mapped[str] = mapped_column(Text)

    dist: Mapped[Optional[DistCpe]] = relationship(lazy='selectin', default=None)

    def merge(self, other: Self) -> None:
        self.deb_version = other.deb_version


class DebsecCve(Base):
    __tablename__ = 'debsec_cve'

    dist_id = mapped_column(ForeignKey(DistCpe.id), primary_key=True)
    gardenlinux_version = Column(Text)
    cve_id: Mapped[str] = mapped_column(primary_key=True)
    last_mod: Mapped[datetime] = mapped_column(init=False, server_default=func.now(), onupdate=func.now())
    deb_source: Mapped[str] = mapped_column(primary_key=True)
    deb_version_fixed: Mapped[Optional[str]] = mapped_column(DebVersion, default=None)
    minor_deb_version_fixed: Mapped[Optional[str]] = mapped_column(default=None)
    debsec_tag: Mapped[Optional[str]] = mapped_column(default=None)
    debsec_note: Mapped[Optional[str]] = mapped_column(default=None)

    dist: Mapped[Optional[DistCpe]] = relationship(lazy='selectin', default=None)

    def merge(self, other: Self) -> None:
        self.deb_version_fixed = other.deb_version_fixed
        self.debsec_tag = other.debsec_tag
        self.debsec_note = other.debsec_note


class DebCve(Base):
    __tablename__ = 'deb_cve'

    dist_id = mapped_column(ForeignKey(DistCpe.id), primary_key=True)
    gardenlinux_version: Mapped[str] = mapped_column(Text)
    cve_id: Mapped[str] = mapped_column(primary_key=True)
    last_mod: Mapped[datetime] = mapped_column(init=False, server_default=func.now(), onupdate=func.now())
    cvss_severity: Mapped[Optional[CvssSeverity]] = mapped_column()
    deb_source: Mapped[str] = mapped_column(primary_key=True)
    deb_version: Mapped[str] = mapped_column(DebVersion)
    deb_version_fixed: Mapped[Optional[str]] = mapped_column(DebVersion)
    debsec_vulnerable: Mapped[bool] = mapped_column()
    data_cpe_match: Mapped[Any]

    dist: Mapped[Optional[DistCpe]] = relationship(lazy='selectin', default=None)

    __table_args__ = (
        Index(
            'deb_cve_search',
            dist_id,
            debsec_vulnerable,
            deb_source,
            deb_version,
        ),
    )

    def merge(self, other: Self) -> None:
        self.cvss_severity = other.cvss_severity
        self.deb_version = other.deb_version
        self.deb_version_fixed = other.deb_version_fixed
        self.debsec_vulnerable = other.debsec_vulnerable
        self.data_cpe_match = other.data_cpe_match


class AllCve(Base):
    __tablename__ = 'all_cve'

    cve_id: Mapped[str] = mapped_column(primary_key=True)
    last_mod: Mapped[datetime] = mapped_column(init=False, server_default=func.now(), onupdate=func.now())
    data: Mapped[Any]

    def merge(self, other: Self) -> None:
        self.data = other.data

class CveContext(Base):
    __tablename__ = 'cve_context'

    cve_id = Column(Text, primary_key=True, nullable=False)
    gardenlinux_version = Column(Text)
    is_resolved = Column(Boolean, nullable=False)
    description = Column(Text)
    use_case = Column(Text)
    dist_id = mapped_column(ForeignKey(DistCpe.id), primary_key=True)

class CveContextKernel(Base):
    __tablename__ = 'cve_context_kernel'

    cve_id = Column(Text, primary_key=True, nullable=False)
    lts_version = Column(Text, primary_key=True, nullable=False)
    fixed_version = Column(Text)
    is_fixed = Column(Boolean, nullable=False)
    is_relevant_subsystem = Column(Boolean, nullable=False)
    source_data = Column(JSONB, nullable=False)
