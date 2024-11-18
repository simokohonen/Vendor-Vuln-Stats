import json
import requests
from collections import Counter
import argparse

def fetch_json(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()  # Raises HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from URL: {e}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON data: {e}")
        return None

def count_vendors(data):
    if not data:
        return {}

    vulnerabilities = data.get("vulnerabilities", [])
    vendor_counts = Counter()

    for vuln in vulnerabilities:
        vendor = vuln.get("vendorProject")
        if vendor:
            vendor_counts[vendor] += 1
        else:
            vendor_counts["Unknown"] += 1  # Handle missing vendor entries

    return dict(vendor_counts)

def save_to_json(vendor_counts, file_path):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(vendor_counts, f, indent=4)
        print(f"\nVendor counts saved to {file_path}")
    except Exception as e:
        print(f"Error saving to file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Count vendor occurrences from CISA KEV JSON feed.")
    parser.add_argument('--output', type=str, help='Path to save the vendor counts as a JSON file.')
    args = parser.parse_args()

    # CISA Known Exploited Vulnerabilities JSON Feed URL
    cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    print("Fetching data from CISA...")
    data = fetch_json(cisa_url)

    if not data:
        print("Failed to retrieve or parse JSON data.")
        return

    print("Counting vendor occurrences...")
    vendor_counts = count_vendors(data)

    if vendor_counts:
        print("\nVendor Counts:")
        # Sort vendors by count in descending order
        sorted_vendors = sorted(vendor_counts.items(), key=lambda item: item[1], reverse=True)
        for vendor, count in sorted_vendors:
            print(f"{vendor}: {count}")
        
        # Save to JSON file if --output is specified
        if args.output:
            # Convert sorted list back to dictionary to preserve order (Python 3.7+)
            sorted_vendor_dict = dict(sorted_vendors)
            save_to_json(sorted_vendor_dict, args.output)
    else:
        print("No vendor data found.")

if __name__ == "__main__":
    main()
