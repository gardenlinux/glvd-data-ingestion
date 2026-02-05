import sys

def get_next_unreleased_versions(version_string: str) -> str:
    """ Get one long string with many Garden Linux Versions included
        find the next minor version for each major version.

    >>> get_next_unreleased_versions("1592.4")
    '1592.5'
    >>> get_next_unreleased_versions("1877.10.0")
    '1877.11'
    >>> get_next_unreleased_versions("2345.0")
    '2345.1.0'
    >>> get_next_unreleased_versions("1877.10 1877.9 1592.4 1592.3 2345.1")
    '1592.5 1877.11 2345.2.0'

    """

    garden_linux_versions = version_string.split()
    versions = {}

    for version in garden_linux_versions:
        major, minor = map(int, version.split('.')[:2])

        if major not in versions:
            versions[major] = minor
        else:
            versions[major] = max(versions[major], minor)


    next_versions = []
    for major, minor in sorted(versions.items()):
         next_version = f"{major}.{minor + 1}"
         if major >= 2013:
             next_version += ".0"
         next_versions.append(next_version)

    
    return ' '.join(next_versions)

if __name__ == "__main__":
    import doctest
    doctest.testmod()
    if len(sys.argv) != 2:
        print("Usage: python unreleased-patch-versions.py '<version_string>'")
        sys.exit(1)

    input_versions = sys.argv[1]
    print(get_next_unreleased_versions(input_versions))
