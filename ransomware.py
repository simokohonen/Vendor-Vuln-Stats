import requests
import re
import json

base_url = "https://raw.githubusercontent.com/BushidoUK/Ransomware-Vulnerability-Matrix/main/Vulnerabilities/"
# List of individual markdown files which contain the cve's
markdown_files = [
    "Applications.md",
    "FileTransferServers.md",
    "Linux.md",
    "Microsoft.md",
    "NetworkEdge.md",
    "Virtualization.md"
]

def process_markdown(markdown_content, map_all_to=None):
    vendor_vulnerabilities = {}
    lines = markdown_content.splitlines()
    current_vendor = None

    for line in lines:
        # Detect vendor header
        if line.startswith("### `") and line.endswith("`"):
            current_vendor = line.strip("### `")
            if map_all_to:  # Override the vendor name if specified
                current_vendor = map_all_to
            if current_vendor not in vendor_vulnerabilities:
                vendor_vulnerabilities[current_vendor] = 0

        # Detect and count table rows (skip header rows)
        elif "|" in line and current_vendor and not line.startswith("|---"):
            vendor_vulnerabilities[current_vendor] += 1

    return vendor_vulnerabilities

all_vulnerabilities = {}

for file_name in markdown_files:
    url = f"{base_url}{file_name}"
    response = requests.get(url)
    if response.status_code == 200:
        file_content = response.text
        # "microsoft" entry is a bit different as it only has microsoft stuff, so all 
        # vulns under this entry mapped under "microsoft" vendor
        map_all_to = "Microsoft" if file_name == "Microsoft.md" else None
        vulnerabilities = process_markdown(file_content, map_all_to)

        for vendor, count in vulnerabilities.items():
            if vendor in all_vulnerabilities:
                all_vulnerabilities[vendor] += count
            else:
                all_vulnerabilities[vendor] = count
    else:
        print(f"Failed to fetch {file_name} (Status code: {response.status_code})")

output_file = "data/merged_vulnerabilities.json"
with open(output_file, "w") as f:
    json.dump(all_vulnerabilities, f, indent=4)

print(f"Consolidated vulnerabilities data saved to {output_file}")
