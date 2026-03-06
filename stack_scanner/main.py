import datetime
import tempfile
import os
import subprocess
import sys
import json
import base64
import urllib.error
import urllib.parse
import urllib.request

excluded_products = [
    "hello-world",
    "java-base",
    "testing-tools",
    "stackable-base",
    "trino-cli",
    "vector",
    "kcat",
    "kafka-testing-tools",
    "java-devel",
    "statsd_exporter",
]

REGISTRY_URL = "oci.stackable.tech"
HARBOR_API_BASE = f"https://{REGISTRY_URL}/api/v2.0"
MAX_AGE_DAYS = 180

# Additional images to scan that are not part of the regular versioned release.
# These are third-party or infrastructure images referenced by the Stackable platform.
ADDITIONAL_IMAGES = [
    {"project": "sdp", "repository": "csi-node-driver-registrar", "product_name": "csi-node-driver-registrar"},
    {"project": "sdp", "repository": "csi-provisioner", "product_name": "csi-provisioner"},
    {"project": "sdp", "repository": "git-sync/git-sync", "product_name": "git-sync"},
    {"project": "sdp", "repository": "stackable-ui", "product_name": "stackable-ui"},
    {"project": "sdp", "repository": "spark-connect-client", "product_name": "spark-connect-client"},
]


def harbor_api_request(path: str, params: dict | None = None) -> list | dict | None:
    """Make a request to the Harbor API and return parsed JSON, or None on failure."""
    url = f"{HARBOR_API_BASE}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)

    request = urllib.request.Request(url)

    username = os.environ.get("HARBOR_USERNAME")
    password = os.environ.get("HARBOR_PASSWORD")
    if username and password:
        credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
        request.add_header("Authorization", f"Basic {credentials}")

    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read().decode())
    except (urllib.error.URLError, json.JSONDecodeError) as error:
        print(f"Harbor API request failed for {path}: {error}")
        return None


def get_harbor_recent_tags(project: str, repository: str) -> list[str] | None:
    """Return tags pushed within the last MAX_AGE_DAYS days for a Harbor repository.

    Tags belonging to artifacts that have no push_time metadata are included
    conservatively (i.e. treated as recent). Returns None when the Harbor API
    is unreachable so the caller can decide how to handle the failure.
    """
    encoded_repo = urllib.parse.quote(repository, safe="")
    path = f"/projects/{project}/repositories/{encoded_repo}/artifacts"
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=MAX_AGE_DAYS)

    tags: list[str] = []
    page = 1
    page_size = 100

    while True:
        artifacts = harbor_api_request(path, {"page": page, "page_size": page_size, "with_tag": "true"})
        if artifacts is None:
            return None

        if not artifacts:
            break

        for artifact in artifacts:
            artifact_tags = [tag["name"] for tag in (artifact.get("tags") or [])]
            if not artifact_tags:
                continue

            push_time_str = artifact.get("push_time")
            if not push_time_str:
                # No push_time available, include conservatively.
                tags.extend(artifact_tags)
                continue

            try:
                push_time = datetime.datetime.fromisoformat(push_time_str.replace("Z", "+00:00"))
                if push_time >= cutoff:
                    tags.extend(artifact_tags)
            except ValueError:
                # Unparseable timestamp, include conservatively.
                tags.extend(artifact_tags)

        if len(artifacts) < page_size:
            break
        page += 1

    return tags


def get_latest_github_release(owner: str, repo: str) -> str | None:
    """Fetch the tag name of the latest GitHub release for a repository."""
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    request = urllib.request.Request(url)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("User-Agent", "stack-scanner")

    try:
        with urllib.request.urlopen(request) as response:
            data = json.loads(response.read().decode())
            return data["tag_name"]
    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as error:
        print(f"Failed to fetch latest {owner}/{repo} release: {error}")
        return None


def scan_stackablectl(secobserve_api_token: str) -> None:
    """Download and scan the latest stackablectl binary from GitHub releases.

    Uses rootfs mode for both Trivy and Grype, which supports scanning standalone
    binaries for embedded dependency information. Once the project publishes a
    CycloneDX SBOM, this should be replaced with SBOM-based scanning.
    """
    version = get_latest_github_release("stackabletech", "stackable-cockpit")
    if version is None:
        print("WARNING: Could not determine latest stackablectl version, skipping.")
        return

    print(f"Scanning stackablectl {version}")
    binary_name = "stackablectl-x86_64-unknown-linux-gnu"
    download_url = (
        f"https://github.com/stackabletech/stackable-cockpit/releases/download"
        f"/{version}/{binary_name}"
    )
    binary_path = f"/tmp/stackable/{binary_name}"

    request = urllib.request.Request(download_url)
    request.add_header("User-Agent", "stack-scanner")
    try:
        with urllib.request.urlopen(request) as response:
            with open(binary_path, "wb") as f:
                f.write(response.read())
        print(f"Downloaded stackablectl binary to {binary_path}")
    except urllib.error.URLError as error:
        print(f"Failed to download stackablectl binary: {error}")
        return

    scan_binary(secobserve_api_token, binary_name, "stackablectl", version)


def scan_binary(
    secobserve_api_token: str,
    file_name: str,
    product_name: str,
    branch_name: str,
) -> None:
    """Scan a local binary file using Trivy and Grype in rootfs mode.

    The file must reside under /tmp/stackable/ so it is accessible inside the
    scanner container (which mounts that directory to /tmp).
    """
    # Run Trivy
    env = {}
    env["TARGET"] = f"/tmp/{file_name}"
    env["SO_UPLOAD"] = "true"
    env["SO_PRODUCT_NAME"] = product_name
    env["SO_API_BASE_URL"] = "https://secobserve-backend.stackable.tech"
    env["SO_API_TOKEN"] = secobserve_api_token
    env["SO_BRANCH_NAME"] = branch_name
    env["TMPDIR"] = "/tmp/trivy_tmp"
    env["TRIVY_CACHE_DIR"] = "/tmp/trivy_cache"
    env["REPORT_NAME"] = "trivy.json"

    cmd = [
        "docker",
        "run",
        "--entrypoint",
        "/entrypoints/entrypoint_trivy_rootfs.sh",
        "-v",
        "/tmp/stackable:/tmp",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
    ]
    for key, value in env.items():
        cmd.extend(["-e", f"{key}={value}"])
    cmd.append("ghcr.io/secobserve/secobserve-scanners:2026_02")

    print(" ".join(cmd))
    subprocess.run(cmd)

    # Run Grype
    env["FURTHER_PARAMETERS"] = "--by-cve"
    env["GRYPE_DB_CACHE_DIR"] = "/tmp/grype_db_cache"
    env["REPORT_NAME"] = "grype.json"

    cmd = [
        "docker",
        "run",
        "--entrypoint",
        "/entrypoints/entrypoint_grype_rootfs.sh",
        "-v",
        "/tmp/stackable:/tmp",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
    ]
    for key, value in env.items():
        cmd.extend(["-e", f"{key}={value}"])
    cmd.append("ghcr.io/secobserve/secobserve-scanners:2026_02")

    subprocess.run(cmd)


def scan_additional_images(secobserve_api_token: str) -> None:
    """Scan additional images that are not part of the regular versioned Stackable release.

    For each image the Harbor API is queried for tags pushed within the last
    MAX_AGE_DAYS days.  If the API is unreachable the image is skipped with a
    warning; if individual artifacts lack push_time metadata their tags are
    included conservatively.
    """
    for image_config in ADDITIONAL_IMAGES:
        project = image_config["project"]
        repository = image_config["repository"]
        product_name = image_config["product_name"]

        print(f"Querying Harbor API for recent tags of {project}/{repository}...")
        tags = get_harbor_recent_tags(project, repository)

        if tags is None:
            print(
                f"WARNING: Harbor API unavailable for {project}/{repository}. "
                "Skipping – re-run once the registry is reachable."
            )
            continue

        if not tags:
            print(f"No tags pushed within the last {MAX_AGE_DAYS} days for {project}/{repository}, skipping.")
            continue

        print(f"Found {len(tags)} recent tag(s) for {project}/{repository}: {tags}")
        for tag in tags:
            image = f"{REGISTRY_URL}/{project}/{repository}:{tag}"
            scan_image(secobserve_api_token, image, product_name, tag)


def main():
    if len(sys.argv) < 4:
        print(
            "Usage:\n"
            "python main.py scan-release <secobserve_api_token> <release>\n"
            "or\n"
            "python main.py scan-image <secobserve_api_token> <image> <product_name> <product_version>"
        )
        sys.exit(1)

    os.system("rm -rf /tmp/stackable/*")
    os.makedirs("/tmp/stackable/trivy_tmp", exist_ok=True)
    os.makedirs("/tmp/stackable/trivy_cache", exist_ok=True)
    os.makedirs("/tmp/stackable/grype_db_cache", exist_ok=True)

    with tempfile.TemporaryDirectory() as tempdir:
        # dump argv to console
        print(sys.argv)
        if sys.argv[1] == "scan-image":
            secobserve_api_token = sys.argv[2]
            image = sys.argv[3]
            product_name = sys.argv[4]
            scan_image(secobserve_api_token, image, product_name, sys.argv[5])
            sys.exit(0)
        else:
            secobserve_api_token = sys.argv[2]
            release = sys.argv[3]
            checkout = "tags/" + release
            if release == "0.0.0-dev":
                checkout = "main"

            os.system(
                "bash -c 'cd docker-images && git fetch --all && git checkout "
                + checkout
                + " && git pull && cd ..'"
            )

            operators = [
                "airflow",
                "commons",
                "druid",
                "hbase",
                "hdfs",
                "hive",
                "kafka",
                "listener",
                "nifi",
                "opa",
                "opensearch",
                "secret",
                "spark-k8s",
                "superset",
                "trino",
                "zookeeper",
            ]

            for arch in ["amd64", "arm64"]:
                for operator_name in operators:
                    product_name = f"{operator_name}-operator"
                    scan_image(
                        secobserve_api_token,
                        f"{REGISTRY_URL}/sdp/{product_name}:{release}-{arch}",
                        product_name,
                        f"{release}-{arch}",
                    )

                # Check if conf.py exists (old format) or use boil (new format)
                conf_py_path = "docker-images/conf.py"
                if os.path.exists(conf_py_path):
                    # Use old conf.py based approach
                    print("Using conf.py based configuration")
                    from image_tools.args import load_configuration
                    sys.path.append("docker-images")
                    product_versions_config = load_configuration(conf_py_path)

                    for product in product_versions_config.products:
                        product_name: str = product["name"]
                        if product_name in excluded_products:
                            continue
                        for version_dict in product.get("versions", []):
                            version: str = version_dict["product"]
                            product_version = f"{version}-stackable{release}"
                            scan_image(
                                secobserve_api_token,
                                f"{REGISTRY_URL}/sdp/{product_name}:{product_version}-{arch}",
                                product_name,
                                f"{product_version}-{arch}",
                            )
                else:
                    # Use new boil based approach
                    print("Using boil based configuration")
                    result = subprocess.run(
                        ["cargo", "boil", "show", "images"],
                        cwd="docker-images",
                        capture_output=True,
                        text=True,
                    )
                    if result.returncode != 0:
                        print("Failed to get product versions:", result.stderr)
                        sys.exit(1)
                    product_versions = json.loads(result.stdout)

                    for product_name, versions in product_versions.items():
                        if product_name in excluded_products:
                            continue
                        for version in versions:
                            product_version = f"{version}-stackable{release}"
                            scan_image(
                                secobserve_api_token,
                                f"{REGISTRY_URL}/sdp/{product_name}:{product_version}-{arch}",
                                product_name,
                                f"{product_version}-{arch}",
                            )

            # Scan additional infrastructure/third-party images using Harbor API tag discovery.
            # This runs once (not per-arch) because tags from Harbor include the arch suffix
            # already or are arch-agnostic manifests.
            scan_additional_images(secobserve_api_token)

            # Scan the latest stackablectl binary from GitHub releases.
            scan_stackablectl(secobserve_api_token)


def scan_image(
    secobserve_api_token: str,
    image: str,
    product_name: str,
    branch_name: str,
) -> None:
    mode = "sbom"
    extract_sbom_cmd = [
        "cosign",
        "verify-attestation",
        "--type",
        "cyclonedx",
        "--certificate-identity-regexp",
        "^https://github.com/stackabletech/.+/.github/workflows/.+@.+",
        "--certificate-oidc-issuer",
        "https://token.actions.githubusercontent.com",
        image,
    ]
    print(" ".join(extract_sbom_cmd))

    result = subprocess.run(
        extract_sbom_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    if result.returncode == 0:
        cosign_output = json.loads(result.stdout.decode("utf-8"))
        payload = base64.b64decode(cosign_output["payload"]).decode("utf-8")
        sbom = json.loads(payload)["predicate"]

        # Required workaround for Trivy to recognize the OS
        for component in sbom.get("components", []):
            if component.get("type") == "operating-system" and component.get("name") == "rhel":
                component["name"] = "redhat"

        with open("/tmp/stackable/bom.json", "w") as f:
            json.dump(sbom, f)
    else:
        print("No SBOM found, falling back to image mode")
        mode = "image"  # fallback to image mode if no SBOM is available

    # Run Trivy
    env = {}
    env["TARGET"] = image if mode == "image" else "/tmp/bom.json"
    env["SO_UPLOAD"] = "true"
    env["SO_PRODUCT_NAME"] = product_name
    env["SO_API_BASE_URL"] = "https://secobserve-backend.stackable.tech"
    env["SO_API_TOKEN"] = secobserve_api_token
    env["SO_BRANCH_NAME"] = branch_name
    env["TMPDIR"] = "/tmp/trivy_tmp"
    env["TRIVY_CACHE_DIR"] = "/tmp/trivy_cache"
    env["REPORT_NAME"] = "trivy.json"

    cmd = [
        "docker",
        "run",
        "--entrypoint",
        "/entrypoints/entrypoint_trivy_" + mode + ".sh",
        "-v",
        "/tmp/stackable:/tmp",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
    ]

    for key, value in env.items():
        cmd.append("-e")
        cmd.append(f"{key}={value}")

    cmd.append("ghcr.io/secobserve/secobserve-scanners:2026_02")

    print(" ".join(cmd))
    subprocess.run(cmd)

    # Run Grype
    env["FURTHER_PARAMETERS"] = "--by-cve"
    env["GRYPE_DB_CACHE_DIR"] = "/tmp/grype_db_cache"
    env["REPORT_NAME"] = "grype.json"

    cmd = [
        "docker",
        "run",
        "--entrypoint",
        "/entrypoints/entrypoint_grype_" + mode + ".sh",
        "-v",
        "/tmp/stackable:/tmp",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
    ]

    for key, value in env.items():
        cmd.append("-e")
        cmd.append(f"{key}={value}")

    cmd.append("ghcr.io/secobserve/secobserve-scanners:2026_02")

    subprocess.run(cmd)


if __name__ == "__main__":
    main()
