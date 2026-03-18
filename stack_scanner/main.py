import datetime
import os
import re
import shutil
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
SECOBSERVE_API_BASE_URL = "https://secobserve-backend.stackable.tech"
SECOBSERVE_SCANNER_IMAGE = "oci.stackable.tech/sandbox/secobserve-scanners:latest"
DEV_RELEASE = "0.0.0-dev"

_PR_TAG_RE = re.compile(r"-pr\d+")

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
            return json.load(response)
    except (urllib.error.URLError, json.JSONDecodeError) as error:
        print(f"Harbor API request failed for {path}: {error}")
        return None


def _iter_harbor_tagged_artifacts(
    project: str, repository: str
) -> list[tuple[datetime.datetime | None, list[str]]] | None:
    """Paginate all tagged artifacts for a Harbor repository.

    Returns a list of (push_time, tag_names) pairs, where push_time is None when
    the timestamp is missing or unparseable. PR-tagged artifacts are excluded.
    Returns None when the Harbor API is unreachable.
    """
    encoded_repo = urllib.parse.quote(repository, safe="")
    path = f"/projects/{project}/repositories/{encoded_repo}/artifacts"

    result: list[tuple[datetime.datetime | None, list[str]]] = []
    page = 1
    page_size = 100

    while True:
        artifacts = harbor_api_request(path, {"page": page, "page_size": page_size, "with_tag": "true"})
        if artifacts is None:
            return None

        if not artifacts:
            break

        for artifact in artifacts:
            artifact_tags = [
                tag["name"]
                for tag in (artifact.get("tags") or [])
                if not _PR_TAG_RE.search(tag["name"])
            ]
            if not artifact_tags:
                continue

            push_time: datetime.datetime | None = None
            push_time_str = artifact.get("push_time")
            if push_time_str:
                try:
                    push_time = datetime.datetime.fromisoformat(push_time_str.replace("Z", "+00:00"))
                except ValueError:
                    pass

            result.append((push_time, artifact_tags))

        if len(artifacts) < page_size:
            break
        page += 1

    return result


def get_harbor_tags(
    project: str, repository: str
) -> tuple[list[str], str | None] | None:
    """Return (recent_tags, latest_tag) for a Harbor repository in a single API pass.

    recent_tags contains tags pushed within the last MAX_AGE_DAYS days; artifacts
    without a parseable push_time are included conservatively. latest_tag is the
    tag from the most recently pushed artifact with a parseable timestamp, or None.
    Returns None when the Harbor API is unreachable.
    """
    artifact_data = _iter_harbor_tagged_artifacts(project, repository)
    if artifact_data is None:
        return None

    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=MAX_AGE_DAYS)
    recent_tags: list[str] = []
    latest_tag: str | None = None
    latest_time: datetime.datetime | None = None

    for push_time, artifact_tags in artifact_data:
        if push_time is None or push_time >= cutoff:
            recent_tags.extend(artifact_tags)
        if push_time is not None and (latest_time is None or push_time > latest_time):
            latest_time = push_time
            latest_tag = artifact_tags[0]

    return recent_tags, latest_tag


def get_latest_github_release(owner: str, repo: str) -> str | None:
    """Fetch the tag name of the latest GitHub release for a repository."""
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    request = urllib.request.Request(url)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("User-Agent", "stack-scanner")

    try:
        with urllib.request.urlopen(request) as response:
            data = json.load(response)
            return data["tag_name"]
    except (urllib.error.URLError, json.JSONDecodeError, KeyError) as error:
        print(f"Failed to fetch latest {owner}/{repo} release: {error}")
        return None


_STACKABLECTL_SBOMS = [
    "stackablectl-x86_64-unknown-linux-gnu.cdx.xml",
    "stackablectl-aarch64-unknown-linux-gnu.cdx.xml",
]


def scan_stackablectl(secobserve_api_token: str) -> None:
    """Download and scan the latest stackablectl SBOMs from GitHub releases.

    The stackable-cockpit project publishes CycloneDX SBOMs alongside each
    binary.  We download the SBOM files and scan them with Trivy and Grype in
    SBOM mode.
    """
    version = get_latest_github_release("stackabletech", "stackable-cockpit")
    if version is None:
        print("WARNING: Could not determine latest stackablectl version, skipping.")
        return

    print(f"Scanning stackablectl {version}")

    for sbom_name in _STACKABLECTL_SBOMS:
        download_url = (
            f"https://github.com/stackabletech/stackable-cockpit/releases/download"
            f"/{version}/{sbom_name}"
        )
        xml_path = f"/tmp/stackable/{sbom_name}"

        request = urllib.request.Request(download_url)
        request.add_header("User-Agent", "stack-scanner")
        try:
            with urllib.request.urlopen(request) as response:
                with open(xml_path, "wb") as f:
                    f.write(response.read())
            print(f"Downloaded SBOM to {xml_path}")
        except urllib.error.URLError as error:
            print(f"Failed to download SBOM {sbom_name}: {error}")
            continue

        # Trivy does not support CycloneDX XML, so convert to JSON first.
        json_name = sbom_name.replace(".cdx.xml", ".cdx.json")
        json_path = f"/tmp/stackable/{json_name}"
        result = subprocess.run(
            [
                "cyclonedx", "convert",
                "--input-file", xml_path,
                "--input-format", "xml",
                "--output-file", json_path,
                "--output-format", "json",
                "--output-version", "v1_5",
            ],
        )
        if result.returncode != 0:
            print(f"Failed to convert {sbom_name} from XML to JSON")
            continue
        print(f"Converted {xml_path} to {json_path}")

        scan_sbom(secobserve_api_token, json_name, "stackablectl", version)


def _build_base_env(secobserve_api_token: str, product_name: str, branch_name: str) -> dict:
    return {
        "SO_UPLOAD": "true",
        "SO_PRODUCT_NAME": product_name,
        "SO_API_BASE_URL": SECOBSERVE_API_BASE_URL,
        "SO_API_TOKEN": secobserve_api_token,
        "SO_BRANCH_NAME": branch_name,
        "TMPDIR": "/tmp/trivy_tmp",
        "TRIVY_CACHE_DIR": "/tmp/trivy_cache",
        "REPORT_NAME": "trivy.json",
    }


def _build_scanner_cmd(entrypoint: str, env: dict) -> list[str]:
    cmd = [
        "docker", "run",
        "--entrypoint", entrypoint,
        "-v", "/tmp/stackable:/tmp",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
    ]
    for key, value in env.items():
        cmd.extend(["-e", f"{key}={value}"])
    cmd.append(SECOBSERVE_SCANNER_IMAGE)
    return cmd


def scan_sbom(
    secobserve_api_token: str,
    file_name: str,
    product_name: str,
    branch_name: str,
) -> None:
    """Scan a local SBOM file using Trivy and Grype in SBOM mode.

    The file must reside under /tmp/stackable/ so it is accessible inside the
    scanner container (which mounts that directory to /tmp).
    """
    trivy_env = _build_base_env(secobserve_api_token, product_name, branch_name)
    trivy_env["TARGET"] = f"/tmp/{file_name}"

    cmd = _build_scanner_cmd("/entrypoints/entrypoint_trivy_sbom.sh", trivy_env)
    print(" ".join(cmd))
    subprocess.run(cmd)

    grype_env = {
        **trivy_env,
        "FURTHER_PARAMETERS": "--by-cve",
        "GRYPE_DB_CACHE_DIR": "/tmp/grype_db_cache",
        "REPORT_NAME": "grype.json",
    }
    cmd = _build_scanner_cmd("/entrypoints/entrypoint_grype_sbom.sh", grype_env)
    subprocess.run(cmd)


_ARCH_SUFFIXES = ("-amd64", "-arm64")


def _filter_redundant_manifest_tags(tags: list[str]) -> list[str]:
    """Remove non-arch-specific tags when arch-specific variants exist.

    For example, if both "v4.5.1" and "v4.5.1-amd64" are present, the plain
    "v4.5.1" tag is dropped because the arch-specific tags already cover it.
    """
    arch_bases = {
        tag.removesuffix(suffix)
        for tag in tags
        for suffix in _ARCH_SUFFIXES
        if tag.endswith(suffix)
    }
    return [tag for tag in tags if tag not in arch_bases or tag.endswith(_ARCH_SUFFIXES)]


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
        result = get_harbor_tags(project, repository)

        if result is None:
            print(
                f"WARNING: Harbor API unavailable for {project}/{repository}. "
                "Skipping – re-run once the registry is reachable."
            )
            continue

        recent_tags, latest_tag = result
        if recent_tags:
            tags = _filter_redundant_manifest_tags(recent_tags)
            print(f"Found {len(tags)} recent tag(s) for {project}/{repository}: {tags}")
        elif latest_tag is not None:
            print(
                f"No tags pushed within the last {MAX_AGE_DAYS} days for {project}/{repository}, "
                "falling back to most recently pushed tag."
            )
            tags = [latest_tag]
        else:
            print(f"WARNING: No tagged artifacts found for {project}/{repository}, skipping.")
            continue

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

    shutil.rmtree("/tmp/stackable", ignore_errors=True)
    os.makedirs("/tmp/stackable/trivy_tmp", exist_ok=True)
    os.makedirs("/tmp/stackable/trivy_cache", exist_ok=True)
    os.makedirs("/tmp/stackable/grype_db_cache", exist_ok=True)

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
        checkout = "main" if release == DEV_RELEASE else "tags/" + release

        subprocess.run(["git", "fetch", "--all"], cwd="docker-images")
        subprocess.run(["git", "checkout", checkout], cwd="docker-images")
        subprocess.run(["git", "pull"], cwd="docker-images")

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

        # Load product version configuration once, outside the arch loop.
        conf_py_path = "docker-images/conf.py"
        if os.path.exists(conf_py_path):
            print("Using conf.py based configuration")
            sys.path.insert(0, os.path.abspath("docker-images"))
            from image_tools.args import load_configuration
            product_versions_config = load_configuration(conf_py_path)
            use_conf_py = True
        else:
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
            use_conf_py = False

        for arch in ["amd64", "arm64"]:
            for operator_name in operators:
                product_name = f"{operator_name}-operator"
                scan_image(
                    secobserve_api_token,
                    f"{REGISTRY_URL}/sdp/{product_name}:{release}-{arch}",
                    product_name,
                    f"{release}-{arch}",
                )

            if use_conf_py:
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
        # Only run for the dev release to avoid redundant scans when multiple releases
        # are processed in the same workflow run (stackablectl is release-independent).
        if release == DEV_RELEASE:
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

    trivy_env = _build_base_env(secobserve_api_token, product_name, branch_name)
    trivy_env["TARGET"] = image if mode == "image" else "/tmp/bom.json"

    cmd = _build_scanner_cmd(f"/entrypoints/entrypoint_trivy_{mode}.sh", trivy_env)
    print(" ".join(cmd))
    subprocess.run(cmd)

    grype_env = {
        **trivy_env,
        "FURTHER_PARAMETERS": "--by-cve",
        "GRYPE_DB_CACHE_DIR": "/tmp/grype_db_cache",
        "REPORT_NAME": "grype.json",
    }
    cmd = _build_scanner_cmd(f"/entrypoints/entrypoint_grype_{mode}.sh", grype_env)
    subprocess.run(cmd)


if __name__ == "__main__":
    main()
