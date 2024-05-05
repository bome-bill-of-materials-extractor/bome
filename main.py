import argparse
import sys
import json
import snyk_test_normalizer

def merge_metadata(main_bome, bome):
    if not main_bome.get("metadata"):
        main_bome['metadata'] = {}
    if not bome.get("metadata"):
        bome['metadata'] = {}
    return dict(bome.get("metadata"), main_bome.get("metadata"))

def merge_app_dependencies(main_bome, bome):
    if not main_bome.get("app_dependencies"):
        main_bome['app_dependencies'] = []
    if not bome.get("app_dependencies"):
        bome['app_dependencies'] = []
    for dep in bome.get("app_dependencies"):
        if dep not in main_bome.get("app_dependencies"):
            main_bome["app_dependencies"].append(dep)
    return main_bome["app_dependencies"]

def merge_os_dependencies(main_bome, bome):
    if not main_bome.get("os_dependencies"):
        main_bome['os_dependencies'] = []
    if not bome.get("os_dependencies"):
        bome['os_dependencies'] = []
    for dep in bome.get("os_dependencies"):
        dep["type"] = "operating-system"
        if dep not in main_bome.get("os_dependencies"):
            main_bome["os_dependencies"].append(dep)
    return main_bome["os_dependencies"]

def merge_container_dependencies(main_bome, bome):
    if not main_bome.get("container_dependencies"):
        main_bome['container_dependencies'] = []
    if not bome.get("container_dependencies"):
        bome['container_dependencies'] = []
    for dep in bome.get("container_dependencies"):
        dep["type"] = "container"
        if dep not in main_bome.get("container_dependencies"):
            main_bome["container_dependencies"].append(dep)
    return main_bome["container_dependencies"]

def merge_vulnerabilities(main_bome, bome):
    if not main_bome.get("vulnerabilities"):
        main_bome['vulnerabilities'] = []
    if not bome.get("vulnerabilities"):
        bome['vulnerabilities'] = []
    for dep in bome.get("vulnerabilities"):
        if dep not in main_bome.get("vulnerabilities"):
            main_bome["vulnerabilities"].append(dep)
    return main_bome["vulnerabilities"]

def merge(bomes):
    main_bome = bomes[0]
    for bome in bomes:
        main_bome["metadata"] = merge_metadata(main_bome, bome)
        main_bome["app_dependencies"] = merge_app_dependencies(main_bome, bome)
        main_bome["os_dependencies"] = merge_os_dependencies(main_bome, bome)
        main_bome["container_dependencies"] = merge_container_dependencies(main_bome, bome)
        main_bome["vulnerabilities"] = merge_vulnerabilities(main_bome, bome)
    return main_bome

def bome_to_vulns(bome):
    vulns = []
    for bome_vuln in bome.get("vulnerabilities"):
        vuln = {
            "id": bome_vuln.get("id"),
            "rating": [{
                "score": bome_vuln.get("score"),
                "severity": bome_vuln.get("severity")
            }],
            "description": bome_vuln.get("description"),
            "source": {"url": bome_vuln.get("url")},
            "created": bome_vuln.get("created")
        }
        vulns.append(vuln)
    return vulns

def spdx(bome):
    cyclone(bome)

def cyclone(bome):
    components = bome.get("app_dependencies") + bome.get("os_dependencies") + bome.get("container_dependencies")
    vulnerabilities = bome_to_vulns(bome)
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": bome.get("version"),
        "metadata": {
            "timestamp": bome.get("metadata").get("date"),
            "authors": bome.get("metadata").get("authors")
        },
        "components": components,
        "vulnerabilities": vulnerabilities
    }
    return sbom
    

def convert(args):
    if args.update_bome:
        with open(args.update_bome) as f:
            bome = json.load(f)
            if not bome.get('version'):
                bome['version'] == 1
            else:
                bome['version'] = bome['version'] + 1
    else:
        bome = {
            "version": 1,
        }
    bomes = [bome]
    if args.snyk_test:
        snyk_test_bome = snyk_test_normalizer.convert(args.snyk_test)
        bomes.append(snyk_test_bome)
    merged_bome = merge(bomes)
    if args.type == "cyclonedx":
        sbom = cyclone(merged_bome)
    else:
        sbom = spdx(merged_bome)
    with open(args.output_file, 'w') as f:
        json.dump(sbom, f)
    

def main(args=None):
    if args is None:
        args = sys.argv[1:]
    convert(args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--snyk-test", help="The location of the json to convert from `snyk test`", nargs='?')
    parser.add_argument("--update-bome", help="The location of the bome, if you want to update it rather than start from scratch", default="", nargs='?')
    parser.add_argument("--output-file", help="The location of the file to save the output", default="output.json", nargs='?')
    parser.add_argument("--type", help="SBOM type: cyclonedx", default="cyclonedx", nargs='?', choices=["cyclonedx"]) # TODO Will add spdx later
    args = parser.parse_args()
    main(args)