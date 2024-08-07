from urllib.request import urlretrieve
from image_tools.args import load_configuration
import tempfile
import os
import subprocess
import sys

excluded_products = [
    "hello-world",
    "java-base",
    "testing-tools",
    "stackable-base",
    "trino-cli",
    "vector",
    "omid",
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

    os.makedirs("/tmp/stackable", exist_ok=True)
    os.system("rm -rf /tmp/stackable/*")

    with tempfile.TemporaryDirectory() as tempdir:
        # dump argv to console
        print(sys.argv)
        if sys.argv[1] == "scan-image":
            secobserve_api_token = sys.argv[2]
            image = sys.argv[3]
            product_name = sys.argv[4]
            product_version = sys.argv[5]
            scan_image(secobserve_api_token, image, product_name, product_version)
            sys.exit(0)
        else:
            secobserve_api_token = sys.argv[2]
            release = sys.argv[3]
            checkout = "tags/" + release
            if release == "0.0.0-dev":
                checkout = "main"

            os.system("bash -c 'cd docker-images && git fetch --all && git checkout " + checkout + " && git pull && cd ..'")

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

            for operator_name in operators:
                product_name = f"{operator_name}-operator"
                scan_image(secobserve_api_token, f"{REGISTRY_URL}/stackable/{product_name}:{release}", product_name, release)

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
                        f"{REGISTRY_URL}/stackable/{product_name}:{product_version}",
                        product_name,
                        product_version,
                    )


def scan_image(secobserve_api_token: str, image: str, product_name: str, product_version: str) -> None:
    # Run Trivy
    env = {}
    env["TARGET"] = image
    env["SO_UPLOAD"] = "true"
    env["SO_PRODUCT_NAME"] = product_name
    env["SO_API_BASE_URL"] = "https://secobserve-backend.stackable.tech"
    env["SO_API_TOKEN"] = secobserve_api_token
    env["SO_BRANCH_NAME"] = product_version
    env["TMPDIR"] = "/tmp"
    env["REPORT_NAME"] = "trivy.json"

    print(f"Scanning {env['TARGET']} with Trivy")

    cmd = [
        "docker",
        "run",
        "--entrypoint",
        "/entrypoints/entrypoint_trivy_image.sh",
        "-v",
        "/tmp/stackable:/tmp",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
    ]

    for key, value in env.items():
        cmd.append("-e")
        cmd.append(f"{key}={value}")

    cmd.append("maibornwolff/secobserve-scanners:latest")

    subprocess.run(cmd)

    # Run Grype
    print(f"Scanning {env['TARGET']} with Grype")

    env["FURTHER_PARAMETERS"] = "--by-cve"
    env["GRYPE_DB_CACHE_DIR"] = "/tmp"
    env["REPORT_NAME"] = "grype.json"

    cmd = [
        "docker",
        "run",
        "--entrypoint",
        "/entrypoints/entrypoint_grype_image.sh",
        "-v",
        "/tmp/stackable:/tmp",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
    ]

    for key, value in env.items():
        cmd.append("-e")
        cmd.append(f"{key}={value}")

    cmd.append("maibornwolff/secobserve-scanners:latest")

    subprocess.run(cmd)


if __name__ == "__main__":
    main()
