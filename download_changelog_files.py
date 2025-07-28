import logging
import requests
import lzma
import tarfile
import io
import re
import gzip
import os
import shutil
import tempfile
import hashlib

# todo: move - utils

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger('download_changelog_files')


def download_apt_index_files():
    # Download releases-patch.json and extract versions with source_repo==true
    releases_url = "https://gardenlinux-glrd.s3.eu-central-1.amazonaws.com/releases-patch.json"
    try:
        resp = requests.get(releases_url)
        resp.raise_for_status()
        releases_data = resp.json()
    except Exception as e:
        logger.error(f"Failed to download or parse releases-patch.json: {e}")
        releases_data = {"releases": []}

    versions = [
        f"{r['version']['major']}.{r['version']['minor']}"
        for r in releases_data.get("releases", [])
        if r.get("attributes", {}).get("source_repo") is True
    ]

    output_dir = "./lists"
    os.makedirs(output_dir, exist_ok=True)

    for version in versions:
        sources_url = f"https://packages.gardenlinux.io/gardenlinux/dists/{version}/main/source/Sources.gz"
        output_filename = os.path.join(
            output_dir,
            f"packages.gardenlinux.io_gardenlinux_dists_{version}_main_source_Sources"
        )
        logger.info(f"Downloading {sources_url}")
        try:
            resp = requests.get(sources_url, stream=True)
            resp.raise_for_status()
            with tempfile.NamedTemporaryFile(delete=False) as tmp_gz:
                tmp_gz.write(resp.content)
                tmp_gz_path = tmp_gz.name
            with gzip.open(tmp_gz_path, "rb") as gz_in, open(output_filename, "wb") as out_f:
                shutil.copyfileobj(gz_in, out_f)
            os.remove(tmp_gz_path)
            logger.info(f"Wrote {output_filename}")
            
            download_changelogs(output_filename, version)
        except Exception as e:
            logger.error(f"Failed to download or extract {sources_url}: {e}")
            continue


def parse_debian_apt_source_index_file(file_path):
    logger.info(f"Parsing Debian APT source index file: {file_path}")
    try:
        with open(file_path, 'r') as f:
            content = f.read()
    except Exception as e:
        logger.error(f"Failed to read file {file_path}: {e}")
        raise

    entries = re.split(r'\n\s*\n', content.strip())
    results = []

    for entry in entries:
        lines = entry.strip().split('\n')
        format_ = None
        directory = None
        files = []
        in_files_section = False
        package = ''
        version = ''

        for line in lines:
            if line.startswith('Format:'):
                format_ = line.split(':', 1)[1].strip()
            elif line.startswith('Directory:'):
                directory = line.split(':', 1)[1].strip()
            elif line.startswith('Package:'):
                package = line.split(':', 1)[1].strip()
            elif line.startswith('Version:'):
                version = line.split(':', 1)[1].strip()
            elif line.startswith('Files:'):
                in_files_section = True
            elif in_files_section:
                if line.strip() == '':
                    continue
                if line.startswith(' ') or line.startswith('\t'):
                    files.append(line.strip())
                else:
                    in_files_section = False

        # We have special handling for the kernel because we don't use debian's build for that
        if package != 'linux':
            results.append({
                'Format': format_,
                'Directory': directory,
                'Files': files,
                'Package': package,
                'Version': version,
            })

    logger.info(f"Parsed {len(results)} entries from source index file")
    return results


def download_and_extract_changelog(entry, debian_tar_xz_file, gl_version):
    if debian_tar_xz_file != '':
        url = f"https://packages.gardenlinux.io/gardenlinux/{entry['Directory']}/{debian_tar_xz_file}"
        logger.info(f"Downloading {debian_tar_xz_file} from {url}")
        try:
            response = requests.get(url)
            response.raise_for_status()
        except Exception as e:
            logger.error(f"Failed to download {url}: {e}")
            return

        try:
            decompressed = lzma.decompress(response.content)
        except Exception as e:
            logger.error(f"Failed to decompress xz file for {entry['Package']}: {e}")
            return

        try:
            with tarfile.open(fileobj=io.BytesIO(decompressed)) as tar:
                
                for member in tar.getmembers():
                    if member.name.endswith("debian/changelog"):
            
                        changelog_file = tar.extractfile(member)
                        changelog_content = changelog_file.read().decode("utf-8")
                        changelog_dir = f"changelogs/{gl_version}"
                        os.makedirs(changelog_dir, exist_ok=True)
                        output_filename = f"{changelog_dir}/{entry['Package']}_changelog.txt"
                        with open(output_filename, "w", encoding="utf-8") as out_f:
                            out_f.write(changelog_content)
                        logger.info(f"Wrote changelog to {output_filename}")

                        # Write sha256 sum file
                        sha256sum = hashlib.sha256(changelog_content.encode("utf-8")).hexdigest()
                        sha256_filename = f"{output_filename}.sha256"
                        with open(sha256_filename, "w", encoding="utf-8") as sha_f:
                            sha_f.write(sha256sum)
                        logger.info(f"Wrote sha256 sum to {sha256_filename}")

        except Exception as e:
            logger.error(f"Failed to extract or parse changelog for {entry['Package']}: {e}")

def download_changelogs(sources_path, gl_version):
    logger.info(f"Using apt sources file from {sources_path}")

    parsed_entries = parse_debian_apt_source_index_file(sources_path)
    logger.info(f"Found {len(parsed_entries)} entries in source index file")


    for entry in parsed_entries:
        logger.info(f"Processing entry: {entry['Package']} in format {entry['Format']}")
        if entry['Format'] == "3.0 (quilt)":
            # entry['Files'] will contain a .dsc file, an orig tarball and a debian tarball with the debian-folder and the changelog
            debian_tar_xz_file = ''
            for f in entry['Files']:
                if f.endswith('debian.tar.xz') or f.endswith('debian.tar.bz2'):
                    debian_tar_xz_file = f.split(' ')[2]
                    break
            download_and_extract_changelog(entry, debian_tar_xz_file, gl_version)
        elif entry['Format'] == "3.0 (native)":
            # entry['Files'] will contain a .dsc file and a tarball with the actual sources and changelog
            debian_tar_xz_file = ''
            for f in entry['Files']:
                if f.endswith('tar.xz') or f.endswith('tar.bz2'):
                    debian_tar_xz_file = f.split(' ')[2]
                    break
            download_and_extract_changelog(entry, debian_tar_xz_file, gl_version)
        elif entry['Format'] == "1.0":
            # Skipping 1.0 format on purpose, because:
            # this affects only a small number of packages, some of them are self-built by us,
            # and the others don't have much use in Garden Linux such as xorg* or wayland packages,
            # and also there seems to be no standard way to locate the changelog in this format
            logger.debug(f"Skipping format 1.0 for {entry.get('Package', 'unknown')}")
            pass


download_apt_index_files()
