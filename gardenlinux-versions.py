import requests

# automatically create a list of minor versions for a given list of major version

major_versions = ['1443']

found_versions = {}

for m in major_versions:
    found_versions[m] = []

for v in major_versions:
    skipped_versions = []
    for p in range(0,30):
        candidate_version = f'{v}.{p}'
        print(f'testing {candidate_version}')
        r = requests.head(f'https://packages.gardenlinux.io/gardenlinux/dists/{v}.{p}/main/binary-amd64/Packages.gz')
        if r.status_code == 200:
            print(f'found {candidate_version}')
            found_versions[v].append(candidate_version)
            skipped_versions = []
        else:
            skipped_versions.append(candidate_version)

        if len(skipped_versions) > 4:
            break

print(found_versions)
