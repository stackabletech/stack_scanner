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

from typing import Optional


# Product images that are not scanned, either because they never run as part of a
# Stackable Data Platform deployment (build and test images), or because their
# contents are a strict subset of a product image that is already scanned.
#
# The base and subset images are not skipped to save time only: scanning them would
# report the same components a second time, under a product name that no
# deployment actually runs.
excluded_products = [
    # Build-only base images, never pushed to the registry.
    "java-base",
    "stackable-base",
    # Only used to build and test the platform, never deployed with it.
    "java-devel",
    "testing-tools",
    "kafka-testing-tools",
    # java-base is built on top of vector, and the products that do not use
    # java-base are built on top of vector directly, so every component of the
    # vector image is already reported by the product images.
    "vector",
    # Built on top of java-base, and its only other content is the Trino CLI,
    # which its SBOM does not cover: the CLI is downloaded as an extensionless
    # file, so no SBOM generator recognises it as a jar. Scanning the image would
    # therefore report the java-base and vector components a second time without
    # covering the CLI itself.
    "trino-cli",
]

REGISTRY_URL = "oci.stackable.tech"
HARBOR_API_BASE = f"https://{REGISTRY_URL}/api/v2.0"
SDP_PROJECT = "sdp"
MAX_AGE_DAYS = 180
SECOBSERVE_API_BASE_URL = "https://secobserve-backend.stackable.tech"
SECOBSERVE_SCANNER_IMAGE = "oci.stackable.tech/stackable/secobserve-scanners:latest"
DEV_RELEASE = "0.0.0-dev"

_PR_TAG_RE = re.compile(r"-pr\d+")

# Cosign stores signatures, attestations and SBOMs as separate artifacts tagged
# "sha256-<digest>.sig"/".att"/".sbom". They are not container images and must not
# be scanned.
_COSIGN_TAG_RE = re.compile(r"^sha256-[0-9a-f]{64}\.(sig|att|sbom)$")

# Stable release tags follow calendar versioning, e.g. "26.3.0". Pre-release tags
# such as "26.3.0-rc1" or "24.11.0-test1" carry a suffix and are excluded.
_STABLE_RELEASE_RE = re.compile(r"^\d+\.\d+\.\d+$")

# Additional images to scan that are not part of the regular versioned release.
# These are third-party or infrastructure images referenced by the Stackable platform.
#
# The CSI sidecars are mirrored into our registry only occasionally (see the
# mirror.yaml workflow in docker-images), so their Harbor push_time says when the
# mirror ran, not which tag the platform actually deploys. For those images the
# deployed tag is read from the Helm values of the operators that run them (see
# "helm_values_image" and _CSI_SIDECAR_SOURCES) and scanned in addition to
# whatever recent tags Harbor reports, so both the shipped version and a freshly
# mirrored candidate are covered.
ADDITIONAL_IMAGES = [
    {
        "project": "sdp",
        "repository": "sig-storage/csi-node-driver-registrar",
        "product_name": "csi-node-driver-registrar",
        "helm_values_image": "csi-node-driver-registrar",
    },
    {
        "project": "sdp",
        "repository": "sig-storage/csi-provisioner",
        "product_name": "csi-provisioner",
        "helm_values_image": "csi-provisioner",
    },
    {"project": "sdp", "repository": "cockpit", "product_name": "cockpit"},
]


# The CSI sidecars are deployed by the secret- and listener-operator, which pin the
# tag they run in their Helm values. Mapping each image to the operators and the
# values path holding its tag lets the deployed tags be read from the source of
# truth instead of being hardcoded here.
_CSI_SIDECAR_SOURCES = {
    "csi-provisioner": [
        ("secret-operator", ("csiNodeDriver", "externalProvisioner")),
        ("listener-operator", ("csiProvisioner", "externalProvisioner")),
    ],
    "csi-node-driver-registrar": [
        ("secret-operator", ("csiNodeDriver", "nodeDriverRegistrar")),
        ("listener-operator", ("csiNodeDriver", "nodeDriverRegistrar")),
    ],
}

_HELM_VALUES_URL = (
    "https://raw.githubusercontent.com/stackabletech/{operator}/{ref}"
    "/deploy/helm/{operator}/values.yaml"
)

_helm_values_cache: dict[tuple[str, str], dict | None] = {}


def _get_operator_helm_values(operator: str, release: str) -> dict | None:
    """Fetch and parse the Helm values of an operator for a given release.

    The dev release is read from ``main``, every other release from its git tag, so
    the tags reported for a release are the ones that release actually deploys.
    Returns None when the file cannot be fetched or parsed.
    """
    cache_key = (operator, release)
    if cache_key in _helm_values_cache:
        return _helm_values_cache[cache_key]

    ref = "refs/heads/main" if release == DEV_RELEASE else f"refs/tags/{release}"
    url = _HELM_VALUES_URL.format(operator=operator, ref=ref)

    values: dict | None = None
    try:
        import yaml

        request = urllib.request.Request(url)
        request.add_header("User-Agent", "stack-scanner")
        with urllib.request.urlopen(request) as response:
            values = yaml.safe_load(response.read())
    except ImportError:
        print("WARNING: PyYAML is not available, cannot read operator Helm values.")
    except (urllib.error.URLError, ValueError) as error:
        print(f"WARNING: Could not fetch Helm values from {url}: {error}")

    _helm_values_cache[cache_key] = values
    return values


def get_deployed_sidecar_tags(image_name: str, release: str) -> list[str]:
    """Return the tags a given release deploys for a sidecar image.

    The tags of all operators running the image are collected, because nothing
    guarantees that they pin the same version. An empty list is returned when no
    tag could be determined, in which case the caller falls back to whatever tags
    Harbor reports.
    """
    tags: list[str] = []

    for operator, values_path in _CSI_SIDECAR_SOURCES.get(image_name, []):
        values = _get_operator_helm_values(operator, release)
        if values is None:
            continue

        node: object = values
        for key in (*values_path, "image", "tag"):
            if not isinstance(node, dict) or key not in node:
                print(
                    f"WARNING: {'.'.join(values_path)}.image.tag not found in the "
                    f"{operator} Helm values of {release}."
                )
                node = None
                break
            node = node[key]

        if isinstance(node, str):
            print(f"{operator} ({release}) deploys {image_name}:{node}")
            if node not in tags:
                tags.append(node)

    return tags


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
                and not _COSIGN_TAG_RE.match(tag["name"])
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


def get_project_repositories(project: str) -> set[str] | None:
    """Return all repository names of a Harbor project, without the project prefix.

    Names are relative to the project, so ``sdp/testing-tools/hive`` is returned
    as ``testing-tools/hive``. Returns None when the Harbor API is unreachable.
    """
    repositories: set[str] = set()
    prefix = f"{project}/"
    page = 1
    page_size = 100

    while True:
        result = harbor_api_request(
            f"/projects/{project}/repositories",
            {"page": page, "page_size": page_size},
        )
        if result is None:
            return None

        if not result:
            break

        for repository in result:
            repositories.add(repository["name"].removeprefix(prefix))

        if len(result) < page_size:
            break
        page += 1

    return repositories


_project_repositories: dict[str, set[str] | None] = {}


def repository_exists(project: str, repository: str) -> bool:
    """Check whether a repository is published in a Harbor project.

    ``cargo boil image list`` recurses into build-only local images such as
    ``hadoop/hadoop`` or ``hbase/hbase-opa-authorizer``, which are never pushed to
    the registry. Attempting to scan them wastes a cosign verification, a
    container start and two rejected uploads each, which added up to roughly an
    eighth of the total scan time.

    The repository list is fetched once per project and cached. If Harbor is
    unreachable everything is let through, so an API outage degrades to scanning
    too much rather than silently scanning nothing.
    """
    if project not in _project_repositories:
        repositories = get_project_repositories(project)
        _project_repositories[project] = repositories
        if repositories is None:
            print(
                f"WARNING: Could not list the repositories of Harbor project {project}, "
                "scanning all of its images without filtering."
            )
        else:
            print(f"Found {len(repositories)} repositories in Harbor project {project}")

    repositories = _project_repositories[project]
    if repositories is None:
        return True

    return repository in repositories


# Almost every image is published to the SDP project, so only the exceptions
# configure something else. The result is cached per image name and the cache is
# cleared whenever docker-images is checked out at another release, because an
# image can be published to another project in another release.
_image_projects: dict[str, str] = {}

_REGISTRY_NAMESPACE_RE = re.compile(r"^\s*registry-namespace:\s*(\S+)\s*$", re.MULTILINE)


def _project_from_boil_config(image_name: str, docker_images_dir: str) -> str | None:
    """Return the registry namespace from the boil config of an image, if configured."""
    config_path = os.path.join(docker_images_dir, image_name, "boil-config.toml")
    if not os.path.exists(config_path):
        return None

    try:
        import tomllib

        with open(config_path, "rb") as config_file:
            config = tomllib.load(config_file)
    except (ImportError, ValueError, OSError) as error:
        print(f"WARNING: Could not read {config_path}: {error}")
        return None

    registry = config.get("metadata", {}).get("registries", {}).get(REGISTRY_URL, {})
    return registry.get("namespace")


def _project_from_build_workflow(image_name: str, docker_images_dir: str) -> str | None:
    """Return the registry namespace the build workflow of an image pushes to.

    Some workflow file names spell the image name with underscores, so both
    spellings are tried.
    """
    workflow_dir = os.path.join(docker_images_dir, ".github", "workflows")
    for name in {image_name, image_name.replace("-", "_")}:
        workflow_path = os.path.join(workflow_dir, f"build_{name}.yaml")
        if not os.path.exists(workflow_path):
            continue

        try:
            with open(workflow_path) as workflow_file:
                match = _REGISTRY_NAMESPACE_RE.search(workflow_file.read())
        except OSError as error:
            print(f"WARNING: Could not read {workflow_path}: {error}")
            continue

        if match:
            return match.group(1)

    return None


def get_image_project(image_name: str, docker_images_dir: str = "docker-images") -> str:
    """Return the Harbor project an image is published to.

    The project is the registry namespace the image is pushed to, which is
    "stackable" for spark-connect-client and "sdp" for every other image at the
    time of writing. It is read from the boil config of the image, falling back to
    the build workflow because "metadata.registries" was only introduced after the
    releases that are still being scanned, and finally to the SDP project.
    """
    if image_name in _image_projects:
        return _image_projects[image_name]

    project = (
        _project_from_boil_config(image_name, docker_images_dir)
        or _project_from_build_workflow(image_name, docker_images_dir)
        or SDP_PROJECT
    )

    if project != SDP_PROJECT:
        print(f"{image_name} is published to the Harbor project {project}")

    _image_projects[image_name] = project
    return project


def get_latest_releases(count: int, docker_images_dir: str = "docker-images") -> list[str]:
    """Return the most recent stable SDP release tags from the docker-images repo.

    Releases are calendar-versioned git tags (e.g. "26.3.0"). Pre-release tags
    such as "26.3.0-rc1" are ignored. Tags are fetched first so the result is
    not limited to whatever was already checked out locally.
    """
    subprocess.run(["git", "fetch", "--tags", "--force"], cwd=docker_images_dir)

    result = subprocess.run(
        ["git", "tag"],
        cwd=docker_images_dir,
        capture_output=True,
        text=True,
        check=True,
    )

    releases = [tag for tag in result.stdout.split() if _STABLE_RELEASE_RE.match(tag)]
    releases.sort(key=lambda tag: tuple(int(part) for part in tag.split(".")))
    return releases[-count:]


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


def scan_stackablectl(secobserve_api_token: str, upload_sbom: Optional[bool] = False) -> None:
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

        scan_sbom(secobserve_api_token, json_name, "stackablectl", version, upload_sbom=upload_sbom)


def _build_base_env(secobserve_api_token: str, product_name: str, branch_name: str) -> dict:
    return {
        "SO_PRODUCT_NAME": product_name,
        "SO_API_BASE_URL": SECOBSERVE_API_BASE_URL,
        "SO_API_TOKEN": secobserve_api_token,
        "SO_BRANCH_NAME": branch_name,
        "SO_SUPPRESS_LICENSES": "true",
        "TMPDIR": "/tmp/trivy_tmp",
        "TRIVY_CACHE_DIR": "/tmp/trivy_cache",
        "GRYPE_DB_CACHE_DIR": "/tmp/grype_db_cache",
    }


# Report file names written inside the scanner container. Trivy and Grype scan
# the same target independently into separate files, so they never collide.
_TRIVY_REPORT = "trivy.json"
_GRYPE_REPORT = "grype.json"


def _combined_scan_script(env: dict, mode: str, upload_sbom: Optional[bool] = False) -> str:
    """Return a shell script that scans with Trivy and Grype, then uploads results.

    Trivy and Grype scan the same target independently, so they are launched
    concurrently to cut wall-clock time. Running both in a single container also
    halves the number of ``docker run`` startups per image.

    The uploads are kept sequential on purpose. SecObserve creates the branch on
    first import via ``get_or_create`` and has no request-level transaction, so
    two concurrent uploads for a not-yet-seen tag could race on branch creation.
    Scanning dominates the runtime, so serialising the two uploads costs almost
    nothing.

    The existing per-scanner entrypoints are reused (with ``SO_UPLOAD=false`` so
    they only scan) to avoid duplicating the scanner invocation flags here.
    """

    if upload_sbom:
        if mode == "sbom":
            script = f"SO_FILE_NAME={env.get('TARGET')} file_upload_sbom.sh\n"
        else:
            print(f"Can't upload SBOM because mode is {mode}")
            script = ""
    else:
        script = (
            "export TRIVY_NO_PROGRESS=true\n"
            f"SO_UPLOAD=false REPORT_NAME={_TRIVY_REPORT} /entrypoints/entrypoint_trivy_{mode}.sh &\n"
            "trivy_pid=$!\n"
            f"SO_UPLOAD=false REPORT_NAME={_GRYPE_REPORT} /entrypoints/entrypoint_grype_{mode}.sh &\n"
            "grype_pid=$!\n"
            'wait "$trivy_pid" || echo "WARNING: Trivy scan failed"\n'
            'wait "$grype_pid" || echo "WARNING: Grype scan failed"\n'
            f"if [ -f {_TRIVY_REPORT} ]; then SO_FILE_NAME={_TRIVY_REPORT} SO_PARSER_NAME=CycloneDX "
            'file_upload_observations.sh; else echo "WARNING: no Trivy report to upload"; fi\n'
            f"if [ -f {_GRYPE_REPORT} ]; then SO_FILE_NAME={_GRYPE_REPORT} SO_PARSER_NAME=CycloneDX "
            'file_upload_observations.sh; else echo "WARNING: no Grype report to upload"; fi\n'
        )

    return script


def _run_combined_scan(env: dict, mode: str, upload_sbom: Optional[bool] = False) -> None:
    """Run Trivy and Grype in a single container for one target, then upload."""
    cmd = [
        "docker", "run",
        "--entrypoint", "/bin/sh",
        "-v", "/tmp/stackable:/tmp",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
    ]
    for key, value in env.items():
        cmd.extend(["-e", f"{key}={value}"])
    cmd.append(SECOBSERVE_SCANNER_IMAGE)
    cmd.extend(["-c", _combined_scan_script(env, mode, upload_sbom)])

    print(f"docker run (combined trivy+grype, {mode} mode) TARGET={env.get('TARGET')}")
    subprocess.run(cmd)


def scan_sbom(
    secobserve_api_token: str,
    file_name: str,
    product_name: str,
    branch_name: str,
    upload_sbom: Optional[bool] = False,
) -> None:
    """Scan a local SBOM file using Trivy and Grype in SBOM mode.

    The file must reside under /tmp/stackable/ so it is accessible inside the
    scanner container (which mounts that directory to /tmp).
    """
    env = _build_base_env(secobserve_api_token, product_name, branch_name)
    env["TARGET"] = f"/tmp/{file_name}"
    _run_combined_scan(env, "sbom", upload_sbom=upload_sbom)


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


def scan_additional_images(
    secobserve_api_token: str, release: str, upload_sbom: Optional[bool] = False
) -> None:
    """Scan additional images that are not part of the regular versioned Stackable release.

    For each image the Harbor API is queried for tags pushed within the last
    MAX_AGE_DAYS days.  If the API is unreachable the image is skipped with a
    warning; if individual artifacts lack push_time metadata their tags are
    included conservatively.

    Images configured with "helm_values_image" additionally get the tag deployed by
    the given release scanned, see get_deployed_sidecar_tags.
    """
    for image_config in ADDITIONAL_IMAGES:
        project = image_config["project"]
        repository = image_config["repository"]
        product_name = image_config["product_name"]

        helm_values_image = image_config.get("helm_values_image")
        deployed_tags = (
            get_deployed_sidecar_tags(helm_values_image, release) if helm_values_image else []
        )
        deployed_arch_tags = [
            f"{tag}{suffix}" for tag in deployed_tags for suffix in _ARCH_SUFFIXES
        ]

        print(f"Querying Harbor API for recent tags of {project}/{repository}...")
        result = get_harbor_tags(project, repository)

        if result is None:
            if not deployed_arch_tags:
                print(
                    f"WARNING: Harbor API unavailable for {project}/{repository}. "
                    "Skipping – re-run once the registry is reachable."
                )
                continue
            print(
                f"WARNING: Harbor API unavailable for {project}/{repository}, "
                "scanning the deployed tags only."
            )
            tags = deployed_arch_tags
        else:
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
            elif deployed_arch_tags:
                print(
                    f"No tagged artifacts found for {project}/{repository}, "
                    "scanning the deployed tags only."
                )
                tags = []
            else:
                print(f"WARNING: No tagged artifacts found for {project}/{repository}, skipping.")
                continue

            for tag in deployed_arch_tags:
                if tag not in tags:
                    print(f"Adding deployed tag {tag} for {project}/{repository}")
                    tags.append(tag)

            # The fallback path returns a single tag without filtering, so an
            # arch-less tag can end up next to the arch-specific variants added
            # above. Re-run the filter over the union to drop it.
            tags = _filter_redundant_manifest_tags(tags)

        for tag in tags:
            image = f"{REGISTRY_URL}/{project}/{repository}:{tag}"
            scan_image(secobserve_api_token, image, product_name, tag, upload_sbom=upload_sbom)


def main():
    if len(sys.argv) < 3:
        print(
            "Usage:\n"
            "python main.py scan-release <secobserve_api_token> <release>\n"
            "or\n"
            "python main.py scan-latest <secobserve_api_token>\n"
            "or\n"
            "python main.py scan-image <secobserve_api_token> <image> <product_name> <product_version>"
        )
        sys.exit(1)

    shutil.rmtree("/tmp/stackable", ignore_errors=True)
    os.makedirs("/tmp/stackable/trivy_tmp", exist_ok=True)
    os.makedirs("/tmp/stackable/trivy_cache", exist_ok=True)
    os.makedirs("/tmp/stackable/grype_db_cache", exist_ok=True)

    # Dump the arguments to the console, with the API token in argv[2] left out.
    print([sys.argv[0], sys.argv[1], "<token>", *sys.argv[3:]])
    secobserve_api_token = sys.argv[2]

    if sys.argv[1] == "scan-image":
        image = sys.argv[3]
        product_name = sys.argv[4]
        scan_image(secobserve_api_token, image, product_name, sys.argv[5])
        sys.exit(0)
    elif sys.argv[1] == "scan-latest":
        # Scan the dev release plus the current and previous stable releases.
        # The stable releases are discovered dynamically from the docker-images
        # git tags so the workflow does not need updating on every release.
        releases = [DEV_RELEASE] + get_latest_releases(2)
        print(f"Scanning releases: {releases}")
        for release in releases:
            scan_release(secobserve_api_token, release)
        sys.exit(0)
    elif sys.argv[1] == "upload-sbom-release":
        release = sys.argv[3]
        scan_release(secobserve_api_token, release, upload_sbom=True)
    else:
        release = sys.argv[3]
        scan_release(secobserve_api_token, release)


def _load_product_versions() -> dict[str, list[str]]:
    """Return a mapping of product image name to product versions.

    Older docker-images revisions configure products in ``conf.py``, newer ones in
    boil configuration files, so both sources are supported.
    """
    conf_py_path = "docker-images/conf.py"
    if os.path.exists(conf_py_path):
        print("Using conf.py based configuration")
        sys.path.insert(0, os.path.abspath("docker-images"))
        from image_tools.args import load_configuration

        config = load_configuration(conf_py_path)
        return {
            product["name"]: [version["product"] for version in product.get("versions", [])]
            for product in config.products
        }

    print("Using boil based configuration")
    # boil >= 0.2.0 uses "image list", older versions use "show images"
    result = subprocess.run(
        ["cargo", "boil", "image", "list"],
        cwd="docker-images",
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        result = subprocess.run(
            ["cargo", "boil", "show", "images"],
            cwd="docker-images",
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        print("Failed to get product versions:", result.stderr)
        sys.exit(1)

    return json.loads(result.stdout)


def scan_release(secobserve_api_token: str, release: str, upload_sbom: Optional[bool] = False) -> None:
    """Scan all operator and product images of a single SDP release."""
    checkout = "main" if release == DEV_RELEASE else "tags/" + release

    subprocess.run(["git", "fetch", "--all"], cwd="docker-images")
    subprocess.run(["git", "checkout", checkout], cwd="docker-images")
    subprocess.run(["git", "pull"], cwd="docker-images")

    # The checkout just changed, so projects resolved for another release are stale.
    _image_projects.clear()

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

    # Resolve the product images once, outside the arch loop, so that excluded and
    # unpublished products are reported a single time per release.
    products: list[tuple[str, str, str]] = []
    for product_name, versions in _load_product_versions().items():
        if product_name in excluded_products:
            continue
        project = get_image_project(product_name)
        if not repository_exists(project, product_name):
            print(f"Skipping {product_name}: not published to {REGISTRY_URL}/{project}")
            continue
        products.extend((project, product_name, version) for version in versions)

    print(f"Scanning {release}: {len(operators)} operator and "
          f"{len(products)} product image(s) per arch")

    for arch in ["amd64", "arm64"]:
        for operator_name in operators:
            product_name = f"{operator_name}-operator"
            scan_image(
                secobserve_api_token,
                f"{REGISTRY_URL}/{SDP_PROJECT}/{product_name}:{release}-{arch}",
                product_name,
                f"{release}-{arch}",
                upload_sbom,
            )

        for project, product_name, version in products:
            product_version = f"{version}-stackable{release}"
            scan_image(
                secobserve_api_token,
                f"{REGISTRY_URL}/{project}/{product_name}:{product_version}-{arch}",
                product_name,
                f"{product_version}-{arch}",
                upload_sbom,
            )

    # Scan additional infrastructure/third-party images using Harbor API tag discovery.
    # This runs once (not per-arch) because tags from Harbor include the arch suffix
    # already or are arch-agnostic manifests.
    scan_additional_images(secobserve_api_token, release, upload_sbom=upload_sbom)

    # Scan the latest stackablectl binary from GitHub releases.
    # Only run for the dev release to avoid redundant scans when multiple releases
    # are processed in the same workflow run (stackablectl is release-independent).
    if release == DEV_RELEASE:
        scan_stackablectl(secobserve_api_token, upload_sbom=upload_sbom)


def scan_image(
    secobserve_api_token: str,
    image: str,
    product_name: str,
    branch_name: str,
    upload_sbom: Optional[bool] = False,
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

    env = _build_base_env(secobserve_api_token, product_name, branch_name)
    env["TARGET"] = image if mode == "image" else "/tmp/bom.json"
    _run_combined_scan(env, mode, upload_sbom)


if __name__ == "__main__":
    main()
