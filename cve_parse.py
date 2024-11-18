import requests
import json
from collections import Counter
from datetime import datetime, timedelta
import sys
import argparse
import time

def compute_date_ranges(start_date, end_date, delta_days=120):
    """
    Splits the date range into multiple intervals of delta_days.
    """
    ranges = []
    current_start = start_date
    while current_start < end_date:
        current_end = min(current_start + timedelta(days=delta_days), end_date)
        ranges.append((current_start, current_end))
        current_start = current_end
    return ranges

def format_datetime(dt):
    """
    Formats datetime object to 'YYYY-MM-DDTHH:MM:SS.mmmZ'
    """
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'

def fetch_cve_data(pub_start_date, pub_end_date, results_per_page=2000, sleep_seconds=1):
    """
    Fetches CVE data from the NVD API within the specified date range.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {
        'User-Agent': 'VendorCounterScript/1.0',
        # 'apiKey': 'YOUR_API_KEY'  # Optional: Add your NVD API key here if available
    }

    params = {
        'pubStartDate': pub_start_date,
        'pubEndDate': pub_end_date,
        'cvssV2Severity': 'HIGH',
        'resultsPerPage': results_per_page,
        'startIndex': 0
    }

    vulnerabilities = []
    total_results = None

    while True:
        try:
            response = requests.get(base_url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()

            if total_results is None:
                total_results = data.get('totalResults', 0)
                if total_results == 0:
                    print("No vulnerabilities found for this interval.")
                    break
                print(f"Fetching {total_results} CVEs from {pub_start_date} to {pub_end_date}")

            vuln_batch = data.get('vulnerabilities', [])
            vulnerabilities.extend(vuln_batch)
            print(f"Fetched {len(vulnerabilities)} / {total_results} CVEs")

            if len(vulnerabilities) >= total_results:
                break

            params['startIndex'] += results_per_page
            time.sleep(sleep_seconds)

        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            break
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            break
        except KeyboardInterrupt:
            print("Interrupted by user.")
            break

    return vulnerabilities

def extract_vendor_from_cpe(cpe_string):
    """
    Extracts the vendor name from a CPE 2.3 string.
    """
    try:
        parts = cpe_string.split(':')
        if len(parts) >= 5:
            vendor = parts[3]
            return vendor.replace('_', ' ').title()
        else:
            return "Unknown"
    except:
        return "Unknown"

def count_vendors(vulnerabilities):
    """
    Counts vendor occurrences from CVE data.
    """
    vendor_counter = Counter()

    for vuln in vulnerabilities:
        cve = vuln.get('cve', {})
        configurations = cve.get('configurations', [])
        for config in configurations:
            nodes = config.get('nodes', [])
            for node in nodes:
                cpe_matches = node.get('cpeMatch', [])
                for cpe in cpe_matches:
                    cpe_string = cpe.get('criteria', '')
                    vendor = extract_vendor_from_cpe(cpe_string)
                    vendor_counter[vendor] += 1

    return vendor_counter

def main():
    parser = argparse.ArgumentParser(description="Count vendor occurrences from NVD CVE Data.")
    parser.add_argument('--output', type=str, help='Path to save the vendor counts as a JSON file.')
    args = parser.parse_args()

    now = datetime.utcnow()
    five_years_ago = now - timedelta(days=5*365)

    date_ranges = compute_date_ranges(five_years_ago, now)

    overall_vulnerabilities = []

    for start, end in date_ranges:
        pub_start_date = format_datetime(start)
        pub_end_date = format_datetime(end)
        vulnerabilities = fetch_cve_data(pub_start_date, pub_end_date)
        overall_vulnerabilities.extend(vulnerabilities)
        # To comply with rate limits
        time.sleep(1)

    print(f"\nTotal CVEs fetched: {len(overall_vulnerabilities)}")

    if not overall_vulnerabilities:
        print("No vulnerabilities to process.")
        sys.exit(0)

    vendor_counts = count_vendors(overall_vulnerabilities)

    if vendor_counts:
        print("\nVendor Counts:")
        sorted_vendors = sorted(vendor_counts.items(), key=lambda item: item[1], reverse=True)
        for vendor, count in sorted_vendors:
            print(f"{vendor}: {count}")
    else:
        print("No vendor data found.")

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(vendor_counts, f, indent=4)
            print(f"\nVendor counts saved to {args.output}")
        except Exception as e:
            print(f"Error saving to file: {e}")

if __name__ == "__main__":
    main()
