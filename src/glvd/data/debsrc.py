# SPDX-License-Identifier: MIT

from __future__ import annotations

import re
from typing import TextIO

from ..database import Debsrc
from glvd.util.minor import extract_minor


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
