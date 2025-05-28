import pytest

from glvd.data.debsrc import DebsrcFile, Debsrc


def test_can_parse_debsrc_file():
    expected = {"glibc": Debsrc(deb_source="glibc", deb_version="2.41-6", dist=None)}

    actual = DebsrcFile()
    with open("tests/unit/package-source-list") as f:
        actual.read(f)

    assert actual == expected
