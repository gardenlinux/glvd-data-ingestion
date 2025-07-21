import logging
from debian import changelog
import requests
import lzma
import tarfile
import io
import re
import json
import gzip
import os
import shutil
import tempfile

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


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

        for line in lines:
            if line.startswith('Format:'):
                format_ = line.split(':', 1)[1].strip()
            elif line.startswith('Directory:'):
                directory = line.split(':', 1)[1].strip()
            elif line.startswith('Package:'):
                package = line.split(':', 1)[1].strip()
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
                'Package': package
            })

    logger.info(f"Parsed {len(results)} entries from source index file")
    return results

def download_changelogs(sources_path, gl_version):
    logger.info(f"Using apt sources file from {sources_path}")

    parsed_entries = parse_debian_apt_source_index_file(sources_path)
    logger.info(f"Found {len(parsed_entries)} entries in source index file")


    for entry in parsed_entries:
        logger.info(f"Processing entry: {entry.get('Package', 'unknown')}")
        if entry['Format'] == "3.0 (quilt)":
            debian_tar_xz_file = next((f.split(' ')[2] for f in entry['Files'] if f.endswith('debian.tar.xz')), '')
            if debian_tar_xz_file != '':
                url = f"https://packages.gardenlinux.io/gardenlinux/{entry['Directory']}/{debian_tar_xz_file}"
                logger.info(f"Downloading debian.tar.xz from {url}")
                try:
                    response = requests.get(url)
                    response.raise_for_status()
                except Exception as e:
                    logger.error(f"Failed to download {url}: {e}")
                    continue

                try:
                    decompressed = lzma.decompress(response.content)
                except Exception as e:
                    logger.error(f"Failed to decompress xz file for {entry['Package']}: {e}")
                    continue

                try:
                    with tarfile.open(fileobj=io.BytesIO(decompressed)) as tar:
                        changelog_member = tar.getmember("debian/changelog")
                        changelog_file = tar.extractfile(changelog_member)
                        changelog_content = changelog_file.read().decode("utf-8")
                        changelog_dir = f"changelogs/{gl_version}"
                        os.makedirs(changelog_dir, exist_ok=True)
                        output_filename = f"{changelog_dir}/{entry['Package']}_changelog.txt"
                        with open(output_filename, "w", encoding="utf-8") as out_f:
                            out_f.write(changelog_content)
                        logger.info(f"Wrote changelog to {output_filename}")

                except Exception as e:
                    logger.error(f"Failed to extract or parse changelog for {entry['Package']}: {e}")
                    continue
        elif entry['Format'] == "3.0 (native)":
            logger.debug(f"Skipping native format for {entry.get('Package', 'unknown')}")
            pass
        elif entry['Format'] == "1.0":
            logger.debug(f"Skipping format 1.0 for {entry.get('Package', 'unknown')}")
            pass


download_apt_index_files()
