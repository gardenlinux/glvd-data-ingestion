import requests
import json
from datetime import date

current_version = 1443
version_today = (date.today() - date(2020, 3, 31)).days

found_versions = {}

while current_version < version_today:
    skipped_versions = []
    found_versions[str(current_version)] = []
    for patch_version in range(0,30):
        candidate_version = f'{current_version}.{patch_version}'
        print(f'testing {candidate_version}')
        r = requests.head(f'https://packages.gardenlinux.io/gardenlinux/dists/{current_version}.{patch_version}/main/binary-amd64/Packages.gz')
        if r.status_code == 200:
            print(f'found {candidate_version}')
            found_versions[str(current_version)].append(candidate_version)
            skipped_versions = []
        else:
            skipped_versions.append(candidate_version)

        if len(skipped_versions) > 4:
            break

    current_version += 1

print(found_versions)

with open('gardenlinux-versions.json', 'w', encoding='utf-8') as f:
    json.dump(found_versions, f, ensure_ascii=False, indent=4)
