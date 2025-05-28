import pytest

import json

from glvd.data.debsec_cve import DebsecCveFile, DebsecCve


def test_can_parse_debsec_cve_file():
    expected = {
        "bookworm": {
            ("CVE-2023-5344", "vim"): DebsecCve(
                cve_id="CVE-2023-5344",
                deb_source="vim",
                deb_version_fixed="2:9.0.1378-2+deb12u1",
                debsec_tag=None,
                debsec_note=None,
                dist=None,
            ),
            ("CVE-2024-33601", "glibc"): DebsecCve(
                cve_id="CVE-2024-33601",
                deb_source="glibc",
                deb_version_fixed="2.36-9+deb12u7",
                debsec_tag=None,
                debsec_note=None,
                dist=None,
            ),
        },
        "bullseye": {
            ("CVE-2023-5344", "vim"): DebsecCve(
                cve_id="CVE-2023-5344",
                deb_source="vim",
                deb_version_fixed="2:8.2.2434-3+deb11u2",
                debsec_tag=None,
                debsec_note=None,
                dist=None,
            ),
            ("CVE-2024-33601", "glibc"): DebsecCve(
                cve_id="CVE-2024-33601",
                deb_source="glibc",
                deb_version_fixed="2.31-13+deb11u10",
                debsec_tag=None,
                debsec_note=None,
                dist=None,
            ),
        },
        "trixie": {
            ("CVE-2023-5344", "vim"): DebsecCve(
                cve_id="CVE-2023-5344",
                deb_source="vim",
                deb_version_fixed="2:9.0.2018-1",
                debsec_tag=None,
                debsec_note=None,
                dist=None,
            ),
            ("CVE-2024-33601", "glibc"): DebsecCve(
                cve_id="CVE-2024-33601",
                deb_source="glibc",
                deb_version_fixed="2.37-19",
                debsec_tag=None,
                debsec_note=None,
                dist=None,
            ),
        },
    }

    actual = DebsecCveFile()
    with open("tests/unit/debian-security-tracker.json") as f:
        actual.read(json.load(f))

    assert actual == expected
