import json
import argparse
import os

def load_json(file_path):
    """
    Load JSON data from a file.

    Args:
        file_path (str): Path to the JSON file.

    Returns:
        dict: Parsed JSON data.
    """
    if not os.path.isfile(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        exit(1)
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON file '{file_path}': {e}")
        exit(1)
    except Exception as e:
        print(f"Error: An unexpected error occurred while loading '{file_path}': {e}")
        exit(1)

def sum_normalize(count, total):
    """
    Normalize a count using Sum normalization.

    Args:
        count (int): The count to normalize.
        total (int): The total sum of counts.

    Returns:
        float: Normalized value between 0 and 1.
    """
    if total == 0:
        return 0
    return count / total

def calculate_danger_index(cve_counts, cisa_counts, ransomware_counts, 
                           weight_cve=0.2, weight_cisa=0.3, weight_ransomware=0.5):
    """
    Calculate the Most Dangerous Vendor Index using Sum Normalization.

    Args:
        cve_counts (dict): Vendor to CVE counts.
        cisa_counts (dict): Vendor to CISA KEV counts.
        ransomware_counts (dict): Vendor to ransomware list counts.
        weight_cve (float): Weight for CVE counts.
        weight_cisa (float): Weight for CISA counts.
        weight_ransomware (float): Weight for ransomware counts.

    Returns:
        dict: Vendor to Danger Index scores.
    """
    # Filter vendors present in all three data sources
    filtered_vendors = set(cve_counts.keys()).intersection(set(cisa_counts.keys())).intersection(set(ransomware_counts.keys()))
    
    # Extract filtered counts
    filtered_cve = {vendor: cve_counts[vendor] for vendor in filtered_vendors}
    filtered_cisa = {vendor: cisa_counts[vendor] for vendor in filtered_vendors}
    filtered_ransomware = {vendor: ransomware_counts[vendor] for vendor in filtered_vendors}
    
    # Calculate total counts for normalization
    total_cve = sum(filtered_cve.values())
    total_cisa = sum(filtered_cisa.values())
    total_ransomware = sum(filtered_ransomware.values())
    
    danger_index = {}
    for vendor in filtered_vendors:
        cve = filtered_cve[vendor]
        cisa = filtered_cisa[vendor]
        ransomware = filtered_ransomware[vendor]
        
        norm_cve = sum_normalize(cve, total_cve)
        norm_cisa = sum_normalize(cisa, total_cisa)
        norm_ransomware = sum_normalize(ransomware, total_ransomware)
        
        # Weighted sum of normalized metrics
        di = (weight_cve * norm_cve) + (weight_cisa * norm_cisa) + (weight_ransomware * norm_ransomware)
        danger_index[vendor] = di
    
    return danger_index

def scale_danger_index(danger_index):
    """
    Scale the Danger Index so that the highest score is 100.

    Args:
        danger_index (dict): Vendor to DI scores.

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
    """
    Save data to a JSON file.

    Args:
        data (dict): Data to save.
        file_path (str): Path to the output JSON file.
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        print(f"\nDanger index saved to '{file_path}'.")
    except Exception as e:
        print(f"Error: Failed to save JSON to '{file_path}': {e}")

def main():
    parser = argparse.ArgumentParser(description="Calculate the Most Dangerous Vendor Index by filtering CVEs and CISA KEV list, including ransomware actor appearances, using Sum Normalization and scaling.")
    parser.add_argument('--cve_file', type=str, required=True, help='Path to cve_counts.json')
    parser.add_argument('--cisa_file', type=str, required=True, help='Path to cisa_counts.json')
    parser.add_argument('--ransomware_file', type=str, required=True, help='Path to ransomware_actors_counts.json')
    parser.add_argument('--output', type=str, help='Path to save the danger index as a JSON file')
    parser.add_argument('--weight_cve', type=float, default=0.4, help='Weight for CVE counts (default: 0.4)')
    parser.add_argument('--weight_cisa', type=float, default=0.35, help='Weight for CISA counts (default: 0.35)')
    parser.add_argument('--weight_ransomware', type=float, default=0.25, help='Weight for ransomware appearances (default: 0.25)')
    
    args = parser.parse_args()
    
    # Validate that weights sum to 1
    total_weight = args.weight_cve + args.weight_cisa + args.weight_ransomware
    if not abs(total_weight - 1.0) < 1e-6:
        print("Error: The sum of weights (weight_cve + weight_cisa + weight_ransomware) must equal 1.")
        exit(1)
    
    # Load data
    cve_counts = load_json(args.cve_file)
    cisa_counts = load_json(args.cisa_file)
    ransomware_counts = load_json(args.ransomware_file)
    
    # Calculate initial Danger Index
    danger_index = calculate_danger_index(
        cve_counts,
        cisa_counts,
        ransomware_counts,
        weight_cve=args.weight_cve,
        weight_cisa=args.weight_cisa,
        weight_ransomware=args.weight_ransomware
    )
    
    # Scale the Danger Index
    scaled_danger_index = scale_danger_index(danger_index)
    
    # Sort vendors by scaled Danger Index descending
    sorted_vendors = sorted(scaled_danger_index.items(), key=lambda item: item[1], reverse=True)
    
    # Display results
    print("\nMost Dangerous Vendor Index:")
    for vendor, di in sorted_vendors:
        print(f"{vendor}: {di}")
    
    # Save to file if --output is specified
    if args.output:
        save_to_json(sorted_vendors, args.output)

if __name__ == "__main__":
    main()
