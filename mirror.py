import json
import subprocess
import sys
import hashlib
import base64
import tempfile
import os
import urllib.request
import urllib.parse
import logging
import re

def parse_new_archive_urls(first_commit, last_commit):
    # Calculate changed files since last synced commit
    if first_commit == last_commit:
        # If first and last commit are the same, show files changed in that specific commit
        lines = subprocess.check_output(
            ["git", "show", "--name-only", "--pretty=format:", last_commit]
        ).decode("utf-8").splitlines()
    else:
        # Show files changed between the two commits
        lines = subprocess.check_output(
            ["git", "diff", first_commit, last_commit, "--name-only", "--pretty=format:"]
        ).decode("utf-8").splitlines()

    archive_urls = {}
    for line in lines:
        file = line.strip()
        if file.endswith("source.json"):
            with open(file) as f:
                source = json.load(f)
                if not "url" in source or not "integrity" in source:
                    logging.warning(f"Skipping {file}: missing url or integrity")
                    continue
                archive_urls[source["url"]] = source["integrity"]
    return archive_urls

def verify_sri_hash(file_path, expected_sri):
    """Verify the SRI hash of a downloaded file."""
    # Parse the SRI hash format
    if expected_sri.startswith('sha256-'):
        algorithm = 'sha256'
        expected_hash = expected_sri[7:]
    elif expected_sri.startswith('sha384-'):
        algorithm = 'sha384'
        expected_hash = expected_sri[7:]
    elif expected_sri.startswith('sha512-'):
        algorithm = 'sha512'
        expected_hash = expected_sri[7:]
    else:
        raise ValueError(f"Unsupported SRI hash algorithm: {expected_sri}")

    # Calculate the actual hash
    with open(file_path, 'rb') as f:
        if algorithm == 'sha256':
            hasher = hashlib.sha256()
        elif algorithm == 'sha384':
            hasher = hashlib.sha384()
        elif algorithm == 'sha512':
            hasher = hashlib.sha512()

        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)

    actual_hash = base64.b64encode(hasher.digest()).decode('ascii')

    if actual_hash != expected_hash:
        raise ValueError(f"Hash mismatch for {file_path}: expected {expected_hash}, got {actual_hash}")

    return True

def download_archive(url, sri_hash, download_dir):
    """Download an archive and verify its SRI hash."""
    filename = os.path.basename(urllib.parse.urlparse(url).path)
    temp_fd, temp_path = tempfile.mkstemp(dir=download_dir, prefix=filename + "-")
    os.close(temp_fd)

    logging.info(f"Downloading {url} to temporary file {temp_path}")
    urllib.request.urlretrieve(url, temp_path)

    logging.info(f"Verifying SRI hash for {filename}")
    verify_sri_hash(temp_path, sri_hash)

    return temp_path

def check_image_exists(image_name, registry_url):
    """Check if an image already exists in the registry."""
    try:
        inspect_cmd = [
            'skopeo', 'inspect',
            f'docker://{registry_url}/{image_name}'
        ]
        result = subprocess.run(inspect_cmd, capture_output=True, text=True)
        if result.returncode == 0:
            logging.info(f"Image {registry_url}/{image_name} already exists, skipping")
            return True
        return False
    except Exception as e:
        logging.debug(f"Error checking image existence: {e}")
        return False

def get_archive_media_type(url):
    """Get the appropriate OCI media type for an archive file based on URL."""
    url_lower = url.lower()
    if url_lower.endswith('.tar.gz') or url_lower.endswith('.tgz'):
        return "application/vnd.oci.image.layer.v1.tar+gzip"
    elif url_lower.endswith('.tar'):
        return "application/vnd.oci.image.layer.v1.tar"
    elif url_lower.endswith('.zip'):
        return "application/zip"
    else:
        return None  # Unsupported archive type

def create_oci_manifest(archive_path, source_url, sri_hash):
    """Create an OCI image manifest with the archive as a layer blob."""
    # Get the media type from the source URL
    media_type = get_archive_media_type(source_url)

    if media_type is None:
        raise ValueError(f"Unsupported archive type: {source_url}")

    # Calculate the sha256 hash of the archive file
    with open(archive_path, 'rb') as f:
        archive_data = f.read()

    archive_sha256 = hashlib.sha256(archive_data).hexdigest()
    archive_size = len(archive_data)

    # Create the layer descriptor - the layer digest IS the archive hash
    layer_descriptor = {
        "mediaType": media_type,
        "digest": f"sha256:{archive_sha256}",
        "size": archive_size
    }

    # Create the config descriptor (minimal empty config)
    config_data = {
        "architecture": "amd64",
        "os": "linux",
        "rootfs": {
            "type": "layers",
            "diff_ids": [f"sha256:{archive_sha256}"]
        }
    }

    config_json = json.dumps(config_data, separators=(',', ':')).encode('utf-8')
    config_sha256 = hashlib.sha256(config_json).hexdigest()
    config_size = len(config_json)

    config_descriptor = {
        "mediaType": "application/vnd.oci.image.config.v1+json",
        "digest": f"sha256:{config_sha256}",
        "size": config_size
    }

    # Create the manifest with searchable annotations
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": config_descriptor,
        "layers": [layer_descriptor],
        "annotations": {
            "org.opencontainers.image.source": source_url,
            "org.opencontainers.image.url": source_url,
            "bazel.source.url": source_url,
            "bazel.source.integrity": sri_hash,
            "bazel.archive.sha256": archive_sha256,
            "org.opencontainers.image.title": f"Bazel source archive from {source_url}",
            "org.opencontainers.image.description": f"Source archive mirrored from {source_url} with SRI hash {sri_hash}"
        }
    }

    return manifest, config_json, archive_data

def create_oci_image(archive_path, image_name, registry_url, source_url, sri_hash):
    """Create an OCI image where the layer digest matches the archive hash."""
    temp_dir = tempfile.mkdtemp()
    try:
        logging.info(f"Creating OCI image {image_name} with archive hash as layer digest")

        # Create OCI manifest and blobs
        manifest, config_blob, archive_blob = create_oci_manifest(archive_path, source_url, sri_hash)

        # Create OCI layout directory structure
        blobs_dir = os.path.join(temp_dir, 'blobs', 'sha256')
        os.makedirs(blobs_dir, exist_ok=True)

        # Write the archive as a blob (layer)
        layer_digest = manifest['layers'][0]['digest'].split(':')[1]
        layer_path = os.path.join(blobs_dir, layer_digest)
        with open(layer_path, 'wb') as f:
            f.write(archive_blob)

        # Write the config as a blob
        config_digest = manifest['config']['digest'].split(':')[1]
        config_path = os.path.join(blobs_dir, config_digest)
        with open(config_path, 'wb') as f:
            f.write(config_blob)

        # Write the manifest as a blob
        manifest_json = json.dumps(manifest, separators=(',', ':')).encode('utf-8')
        manifest_digest = hashlib.sha256(manifest_json).hexdigest()
        manifest_path = os.path.join(blobs_dir, manifest_digest)
        with open(manifest_path, 'wb') as f:
            f.write(manifest_json)

        # Create index.json pointing to our manifest
        index = {
            "schemaVersion": 2,
            "manifests": [{
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": f"sha256:{manifest_digest}",
                "size": len(manifest_json)
            }]
        }

        with open(os.path.join(temp_dir, 'index.json'), 'w') as f:
            json.dump(index, f)

        # Create oci-layout
        with open(os.path.join(temp_dir, 'oci-layout'), 'w') as f:
            json.dump({"imageLayoutVersion": "1.0.0"}, f)

        # Push using skopeo from OCI layout
        push_cmd = [
            'skopeo', 'copy',
            f'oci:{temp_dir}',
            f'docker://{registry_url}/{image_name}'
        ]

        logging.info(f"Pushing OCI image to {registry_url}/{image_name}")
        logging.info(f"Layer digest: sha256:{layer_digest}")
        subprocess.run(push_cmd, check=True)

    finally:
        # Clean up temporary directory
        subprocess.run(['rm', '-rf', temp_dir])

def main():
    if len(sys.argv) != 4:
        print("Usage: python mirror.py <first_commit> <last_commit> <registry_url>")
        return 1

    first_commit, last_commit, registry_url = sys.argv[1:4]

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    try:
        archive_urls = parse_new_archive_urls(first_commit, last_commit)

        if not archive_urls:
            logging.info("No new archives to process")
            return 0

        download_dir = tempfile.mkdtemp()

        try:
            for url, sri_hash in archive_urls.items():
                try:
                    # Generate image name from hash of URL without scheme
                    if url.startswith('https://'):
                        url_without_scheme = url[8:]  # Remove 'https://'
                    elif url.startswith('http://'):
                        url_without_scheme = url[7:]  # Remove 'http://'
                    else:
                        raise ValueError(f"URL must start with http:// or https://: {url}")
                    url_hash = hashlib.sha256(url_without_scheme.encode()).hexdigest()
                    image_name = f"url-sha256-{url_hash}"

                    # Check if image already exists in registry
                    if check_image_exists(image_name, registry_url):
                        continue

                    # Download and verify the archive
                    archive_path = download_archive(url, sri_hash, download_dir)

                    try:
                        # Create and push OCI image
                        create_oci_image(archive_path, image_name, registry_url, url, sri_hash)

                        logging.info(f"Successfully processed {url}")

                    finally:
                        # Clean up the individual archive file
                        if os.path.exists(archive_path):
                            os.unlink(archive_path)

                except Exception as e:
                    logging.error(f"Failed to process {url}: {e}")
                    continue

        finally:
            # Clean up download directory
            subprocess.run(['rm', '-rf', download_dir])

        logging.info("Archive mirroring completed")
        return 0

    except Exception as e:
        logging.error(f"Script failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())