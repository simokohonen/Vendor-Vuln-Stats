import json
import argparse
from collections import Counter

def load_json(file_path):
    """Load JSON data from a file."""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {file_path}: {e}")
        exit(1)

def sum_normalize(count, total):
    """Normalize a count using Sum normalization."""
    if total == 0:
        return 0
    return count / total

def calculate_danger_index(cve_counts, cisa_counts, weight_cve=0.5, weight_cisa=0.5):
    """Calculate the Most Dangerous Vendor Index using Sum Normalization."""
    # Filter vendors present in both cve_counts and cisa_counts
    filtered_vendors = set(cve_counts.keys()).intersection(set(cisa_counts.keys()))
    
    # Extract filtered counts
    filtered_cve = {vendor: cve_counts[vendor] for vendor in filtered_vendors}
    filtered_cisa = {vendor: cisa_counts[vendor] for vendor in filtered_vendors}
    
    # Calculate total counts for normalization
    total_cve = sum(filtered_cve.values())
    total_cisa = sum(filtered_cisa.values())
    
    danger_index = {}
    for vendor in filtered_vendors:
        cve = filtered_cve[vendor]
        cisa = cisa_counts[vendor]
        
        norm_cve = sum_normalize(cve, total_cve)
        norm_cisa = sum_normalize(cisa, total_cisa)
        
        di = (weight_cve * norm_cve) + (weight_cisa * norm_cisa)
        danger_index[vendor] = di
    
    return danger_index

def scale_danger_index(danger_index):
    """
    Scale the Danger Index so that the highest score is 100.
    
    Args:
        danger_index (dict): Dictionary with vendor names as keys and their DI as values.
        
    Returns:
        dict: Scaled Danger Index with values between 0 and 100.
    """
    if not danger_index:
        return {}
    
    max_di = max(danger_index.values())
    if max_di == 0:
        return {vendor: 0 for vendor in danger_index}
    
    scaling_factor = 100 / max_di
    scaled_index = {vendor: round(di * scaling_factor, 2) for vendor, di in danger_index.items()}
    
    return scaled_index

def save_to_json(data, file_path):
    """Save the danger index to a JSON file."""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        print(f"\nDanger index saved to {file_path}")
    except Exception as e:
        print(f"Error saving to {file_path}: {e}")

def main():
    parser = argparse.ArgumentParser(description="Calculate the Most Dangerous Vendor Index by filtering CVEs through CISA KEV list using Sum Normalization and scaling.")
    parser.add_argument('--cve_file', type=str, required=True, help='Path to cve_counts.json')
    parser.add_argument('--cisa_file', type=str, required=True, help='Path to cisa_counts.json')
    parser.add_argument('--output', type=str, help='Path to save the danger index as a JSON file')
    parser.add_argument('--weight_cve', type=float, default=0.5, help='Weight for CVE counts (default: 0.5)')
    parser.add_argument('--weight_cisa', type=float, default=0.5, help='Weight for CISA counts (default: 0.5)')
    
    args = parser.parse_args()
    
    # Load data
    cve_counts = load_json(args.cve_file)
    cisa_counts = load_json(args.cisa_file)
    
    # Calculate danger index
    danger_index = calculate_danger_index(cve_counts, cisa_counts, args.weight_cve, args.weight_cisa)
    
    # Scale the danger index
    scaled_danger_index = scale_danger_index(danger_index)
    
    # Sort vendors by scaled Danger Index descending
    sorted_vendors = sorted(scaled_danger_index.items(), key=lambda item: item[1], reverse=True)
    
    # Display results
    print("\nMost Dangerous Vendor Index:")
    for vendor, di in sorted_vendors:
        print(f"{vendor}: {di}")
    
    # Save to file if --output is specified
    if args.output:
        # Convert to a dictionary with sorted keys
        sorted_vendor_dict = dict(sorted_vendors)
        save_to_json(sorted_vendor_dict, args.output)

if __name__ == "__main__":
    main()
