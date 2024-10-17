from urllib.request import urlretrieve
from image_tools.args import load_configuration
import tempfile
import os
import subprocess
import sys
import json
import base64

excluded_products = [
    "hello-world",
    "java-base",
    "testing-tools",
    "stackable-base",
    "trino-cli",
    "vector",
    "tools",
    "omid",
    "kcat",
    "kafka-testing-tools",
    "java-devel",
    "statsd_exporter",
]

REGISTRY_URL = "docker.stackable.tech"


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
            product_version, arch = sys.argv[5].split("-")
            scan_image(secobserve_api_token, image, product_name, product_version, arch)
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
                "hello-world",
                "hive",
                "kafka",
                "listener",
                "nifi",
                "opa",
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
                        f"{REGISTRY_URL}/stackable/{product_name}:{release}-{arch}",
                        product_name,
                        release,
                        arch,
                    )

                # Load product versions from that file using the image-tools functionality
                sys.path.append("docker-images")
                product_versions = load_configuration("docker-images/conf.py")

                for product in product_versions.products:
                    product_name: str = product["name"]

                    if product_name in excluded_products:
                        continue
                    for version_dict in product.get("versions", []):
                        version: str = version_dict["product"]
                        product_version = f"{version}-stackable{release}"
                        scan_image(
                            secobserve_api_token,
                            f"{REGISTRY_URL}/stackable/{product_name}:{product_version}-{arch}",
                            product_name,
                            product_version,
                            arch,
                        )


def scan_image(
    secobserve_api_token: str,
    image: str,
    product_name: str,
    product_version: str,
    architecture: str,
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
        image.replace("docker.stackable.tech/stackable/", "oci.stackable.tech/sdp/"),
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
    env["SO_BRANCH_NAME"] = product_version + "-" + architecture
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

    cmd.append("oci.stackable.tech/sandbox/secobserve-scanners:latest")

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

    cmd.append("oci.stackable.tech/sandbox/secobserve-scanners:latest")

    subprocess.run(cmd)


if __name__ == "__main__":
    main()
