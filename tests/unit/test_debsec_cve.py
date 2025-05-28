import pytest

from glvd.data.debsec_cve import DebsecCveFile, DebsecCve

def test_can_parse_debsec_cve_file():
    expected = {
        '': {
            ('CVE-2023-5344', 'vim'): DebsecCve(
                cve_id='CVE-2023-5344',
                deb_source='vim',
                deb_version_fixed='2:9.0.2018-1',
                debsec_tag=None,
                debsec_note='bug #1053694',
                dist=None,
            ),
            ('CVE-2024-33601', 'glibc'): DebsecCve(
                cve_id='CVE-2024-33601',
                deb_source='glibc',
                deb_version_fixed='2.37-19',
                debsec_tag=None,
                debsec_note=None,
                dist=None,
            ),
        },
        'bookworm': {
            ('CVE-2023-5344', 'vim'): DebsecCve(
                cve_id='CVE-2023-5344',
                deb_source='vim',
                deb_version_fixed='2:9.0.1378-2+deb12u1',
                debsec_tag=None,
                debsec_note=None,
                dist=None,
            ),
        },
        'buster': {
            ('CVE-2023-5344', 'vim'): DebsecCve(
                cve_id='CVE-2023-5344',
                deb_source='vim',
                deb_version_fixed=None,
                debsec_tag='postponed',
                debsec_note='Minor issue, 1-byte overflow',
                dist=None,
            ),
        },
    }

    actual = DebsecCveFile()
    with open('tests/unit/debsec-cve-list') as f:
        actual.read(f)

    assert actual == expected

