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
    if len(sys.argv) < 3:
        print("Usage: python main.py <release> <secobserve_api_token>")
        sys.exit(1)

    os.makedirs("/tmp/stackable", exist_ok=True)
    os.system("rm -rf /tmp/stackable/*")

    with tempfile.TemporaryDirectory() as tempdir:
        release = sys.argv[1]
        secobserve_api_token = sys.argv[2]
        # Create a file in the temp dir and download the conf.py from the git tag referring to that version
        filename = os.path.join(tempdir, f"products-{release}.py")
        branch = release
        if release == "0.0.0-dev":
            branch = "main"
        url = f"https://raw.githubusercontent.com/stackabletech/docker-images/{branch}/conf.py"
        oldurl = f"https://raw.githubusercontent.com/stackabletech/docker-images/{branch}/image_tools/conf.py"
        print(
            f"Loading product config for version [{release}] from [{url}] (via file [{filename}]"
        )
        try:
            urlretrieve(url, filename)
        except:
            print(
                f"Got 404 for release file, falling back to old file location [{oldurl}]"
            )
            try:
                urlretrieve(oldurl, filename)
            except:
                print(f"Unable to retrieve config file for release [{release}]")
                sys.exit(1)

        operators = ["airflow", "commons", "druid", "hbase", "hdfs", "hello-world", "hive", "kafka", "listener", "nifi", "opa", "secret", "spark-k8s", "superset", "trino", "zookeeper"]

        for operator_name in operators:
            scan_image(secobserve_api_token, f"{operator_name}-operator", release)

        # Free up space after scanning operators
        os.system(
            'docker system prune -f'
        )
        os.system(
            'docker system prune -f -a --filter="label=vendor=Stackable GmbH"'
        )

        # Load product versions from that file using the image-tools functionality
        product_versions = load_configuration(filename)

        for product in product_versions.products:
            product_name: str = product["name"]

            if product_name in excluded_products:
                continue
            for version_dict in product.get("versions", []):
                product_version: str = version_dict["product"]

                scan_image(secobserve_api_token, product_name, f"{product_version}-stackable{release}")

            # Free up space after each product scan
            os.system(
                'docker system prune -f'
            )
            os.system(
                'docker system prune -f -a --filter="label=vendor=Stackable GmbH"'
            )

def scan_image(secobserve_api_token: str, product_name: str, image_tag: str) -> None:
    # Run Trivy
    env = {}
    env["TARGET"] = (
        f"{REGISTRY_URL}/stackable/{product_name}:{image_tag}"
    )
    env["SO_UPLOAD"] = "true"
    env["SO_PRODUCT_NAME"] = product_name
    env["SO_API_BASE_URL"] = "https://secobserve-backend.stackable.tech"
    env["SO_API_TOKEN"] = secobserve_api_token
    env["SO_BRANCH_NAME"] = image_tag
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
