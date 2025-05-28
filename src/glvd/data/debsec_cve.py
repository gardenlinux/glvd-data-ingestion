# SPDX-License-Identifier: MIT

from __future__ import annotations

import json

from ..database import DebsecCve


class DebsecCveFile(dict[str, dict[tuple[str, str], DebsecCve]]):

    def read(self, f: dict) -> None:
        for package, cves in f.items():
            for cve_id, entry in cves.items():
                # Filter out TEMP- and other non-CVE entries
                if cve_id.startswith('CVE-'):
                    for release in entry['releases']:
                        if release != 'sid': 
                            codename = release
                            tag = entry.get("tag")
                            version_fixed = entry['releases'][codename].get('fixed_version')
                            note = entry.get("note")
                            per_codename = self.setdefault(codename, {})
                            per_codename[(cve_id, package)] = DebsecCve(
                                cve_id=cve_id,
                                dist=None,
                                deb_source=package,
                                deb_version_fixed=version_fixed,
                                debsec_tag=tag,
                                debsec_note=note,
                            )


if __name__ == '__main__':
    import sys

    d = DebsecCveFile()
    with open(sys.argv[1]) as f:
        d.read(json.load(f))

    for codename, entries in d.items():
        print(f'Codename: {codename}')
        for entry in entries.values():
            print(f'  {entry!r}')
