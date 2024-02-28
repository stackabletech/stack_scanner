from urllib.request import urlretrieve
from image_tools.args import load_configuration
import tempfile
import os
import subprocess

releases = [
    '23.4.0',
    '23.4.1',
    '23.7.0',
    '23.11.0',
]

excluded_products = [
    'hello-world',
    'java-base',
]

REGISTRY_URL = "docker.stackable.tech"


def main():
    with tempfile.TemporaryDirectory() as tempdir:
        for release in releases:
            # Create a file in the temp dir and download the conf.py from the git tag referring to that version
            filename = os.path.join(tempdir, f"products-{release}.py")
            url = f"https://raw.githubusercontent.com/stackabletech/docker-images/{release}/conf.py"
            oldurl = f"https://raw.githubusercontent.com/stackabletech/docker-images/{release}/image_tools/conf.py"
            print(f"Loading product config for version [{release}] from [{url}] (via file [{filename}]")
            try:
                urlretrieve(url, filename)
            except:
                print(f"Got 404 for release file, falling back to old file location [{oldurl}]")
                try:
                    urlretrieve(oldurl, filename)
                except:
                    print(f"Unable to retrieve config file for release [{release}], skipping ..")
                    continue

            # Load product versions from that file using the image-tools functionality
            product_versions = load_configuration(filename)

            # Generate image names
            product_names: list[str] = [product["name"] for product in product_versions.products]
            for product in product_versions.products:
                product_name: str = product["name"]

                if product_name in excluded_products:
                    continue
                product_targets = {}
                for version_dict in product.get("versions", []):
                    product_version: str = version_dict['product']
                    image_name = f"{REGISTRY_URL}/stackable/{product_name}:{product_version}-stackable{release}"
                    #print(f"Scanning {REGISTRY_URL}/stackable/{product_name}:{product_version}-stackable{release}")
                    print(f"grype -o cyclonedx --file {release}-{product_name}-{product_version}.cdx {image_name}")
                    subprocess.run(["grype", "-o",  "json", "--file", f"release-{product_name}-{product_version}.cdx", f"{image_name}"])



if __name__ == "__main__": main()