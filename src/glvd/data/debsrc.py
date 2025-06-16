# SPDX-License-Identifier: MIT

from __future__ import annotations

import re
from typing import TextIO

from ..database import Debsrc


def extract_minor(version):
    if version is None:
        return ''
    # Remove epoch if present (e.g., '1:' in '1:1.37.0-5')
    version = version.split(':', 1)[-1]
    # Extract the numeric part before any dash or plus
    main_part = re.split(r'[-+]', version)[0]
    # Split by dot and take first two numeric components
    parts = main_part.split('.')
    if len(parts) >= 2:
        return f"{parts[0]}.{parts[1]}"
    elif len(parts) == 1:
        return parts[0]
    else:
        return ''


class DebsrcFile(dict[str, Debsrc]):
    __re = re.compile(r'''
        ^(?:
            Package:\s*(?P<source>[a-z0-9.-]+)
            |
            Version:\s*(?P<version>[A-Za-z0-9.+~:-]+)
            |
            Extra-Source-Only:\s*(?P<eso>yes)
            |
            (?P<eoe>)
            |
            # All other fields
            [A-Za-z0-9-]+:.*
            |
            # Continuation field
            \s+.*
        )$
    ''', re.VERBOSE)

    def _read_source(self, source: str, version: str) -> None:
        self[source] = Debsrc(
            deb_source=source,
            deb_version=version,
            minor_deb_version=extract_minor(version),
        )

    def read(self, f: TextIO) -> None:
        current_source = current_version = None

        def finish():
            if current_source and current_version:
                self._read_source(current_source, current_version)

        for line in f.readlines():
            if match := self.__re.match(line):
                if i := match['source']:
                    current_source = i
                elif i := match['version']:
                    current_version = i
                elif match['eso']:
                    current_source = current_version = None
                elif match['eoe'] is not None:
                    finish()
                    current_source = current_version = None
            else:
                raise RuntimeError(f'Unable to read line: {line}')

        finish()


if __name__ == '__main__':
    import sys

    d = DebsrcFile()
    with open(sys.argv[1]) as f:
        d.read(f)

    for entry in d.values():
        print(f'{entry!r}')
