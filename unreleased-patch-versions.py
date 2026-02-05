import sys

def get_next_unreleased_versions(version_string: str) -> str:
    """ Get one long string with many Garden Linux Versions included
        find the next minor version for each major version.

    >>> get_next_unreleased_versions("1592.4")
    '1592.5'
    >>> get_next_unreleased_versions("1877.10.0")
    '1877.11.0'
    >>> get_next_unreleased_versions("2345.0")
    '2345.1.0'
    >>> get_next_unreleased_versions("1877.10 1592.4 2345.1")
    '1592.5 1877.11.0 2345.2.0'

    """
    versions = version_string.split()
    major_versions = {}

    for version in versions:
        version_split = list(map(int, version.split('.')))
        major = version_split[0]
        minor = version_split[1]

        if major not in major_versions:
            major_versions[major] = minor
        else:
            major_versions[major] = max(major_versions[major], minor)


    next_versions = []
    for major, minor in sorted(major_versions.items()):
         next_version = f"{major}.{minor + 1}"
         if major >= 1877:
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
