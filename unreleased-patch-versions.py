import sys

def get_next_unreleased_versions(version_string):
    versions = version_string.split()
    major_versions = {}

    for version in versions:
        major, minor = map(int, version.split('.'))
        if major not in major_versions:
            major_versions[major] = minor
        else:
            major_versions[major] = max(major_versions[major], minor)

    next_versions = [f"{major}.{minor + 1}" for major, minor in sorted(major_versions.items())]
    return ' '.join(next_versions)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python unreleased-patch-versions.py '<version_string>'")
        sys.exit(1)

    input_versions = sys.argv[1]
    print(get_next_unreleased_versions(input_versions))
