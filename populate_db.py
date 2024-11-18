# populate_db.py

import json
import os
from app import db, app
from models import Vendor
import math 

def load_json(file_path):
    if not os.path.isfile(file_path):
        return {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}
    except Exception:
        return {}

def sum_normalize(count, total):

    if total == 0:
        return 0
    return count / total

def calculate_danger_index(cve_counts, cisa_counts, ransomware_counts, 
                           weight_cve=0.2, weight_cisa=0.3, weight_ransomware=0.5):
    all_vendors = set(cve_counts.keys()).union(cisa_counts.keys()).union(ransomware_counts.keys())

    cve_counts = {vendor: int(count) for vendor, count in cve_counts.items()}
    cisa_counts = {vendor: int(count) for vendor, count in cisa_counts.items()}
    ransomware_counts = {vendor: int(count) for vendor, count in ransomware_counts.items()}

    total_cve = sum(count for count in cve_counts.values() if count > 0)
    total_cisa = sum(count for count in cisa_counts.values() if count > 0)
    total_ransomware = sum(count for count in ransomware_counts.values() if count > 0)

    danger_index = {}

    for vendor in all_vendors:
        # Get counts, defaulting to 0
        cve = cve_counts.get(vendor, 0)
        cisa = cisa_counts.get(vendor, 0)
        ransomware = ransomware_counts.get(vendor, 0)

        # Initialize weights and normalized counts
        norm_cve = norm_cisa = norm_ransomware = 0
        vendor_weight_cve = vendor_weight_cisa = vendor_weight_ransomware = 0

        # Normalize counts and adjust weights only if counts are present
        if cve > 0 and total_cve > 0:
            norm_cve = cve / total_cve
            vendor_weight_cve = weight_cve
        if cisa > 0 and total_cisa > 0:
            norm_cisa = cisa / total_cisa
            vendor_weight_cisa = weight_cisa
        if ransomware > 0 and total_ransomware > 0:
            norm_ransomware = ransomware / total_ransomware
            vendor_weight_ransomware = weight_ransomware

        # Sum of weights for this vendor
        total_vendor_weight = vendor_weight_cve + vendor_weight_cisa + vendor_weight_ransomware

        # If total weight is zero, skip this vendor
        if total_vendor_weight == 0:
            continue

        # Adjust weights proportionally
        adjusted_weight_cve = vendor_weight_cve / total_vendor_weight
        adjusted_weight_cisa = vendor_weight_cisa / total_vendor_weight
        adjusted_weight_ransomware = vendor_weight_ransomware / total_vendor_weight

        # Calculate danger index for the vendor
        di = (adjusted_weight_cve * norm_cve) + (adjusted_weight_cisa * norm_cisa) + (adjusted_weight_ransomware * norm_ransomware)

        danger_index[vendor] = di

    print(f"scored {len(danger_index)} items")
    return danger_index

def scale_danger_index(danger_index):

    if not danger_index:
        return {}

    max_di = max(danger_index.values())
    if max_di == 0:
        return {vendor: 0 for vendor in danger_index}

    scaling_factor = 100 / max_di
    scaled_index = {vendor: round(di * scaling_factor, 2) for vendor, di in danger_index.items()}

    return scaled_index


def populate_database(cve_file, cisa_file, ransomware_file):
    # currently using prebuilt json files, swap with a better routine in the future
    # cve_parse.py creates cve_file
    # parse_cisa.py creates cisa_file
    # ransomware.py creates ransomware_file
    cve_data = load_json(cve_file)
    cisa_data = load_json(cisa_file)
    ransomware_data = load_json(ransomware_file)

    # Calculate danger index using the modified function
    danger_index_raw = calculate_danger_index(cve_data, cisa_data, ransomware_data)
    danger_index_scaled = scale_danger_index(danger_index_raw)

    count = 0
    for vendor, di in danger_index_scaled.items():
        count = count + 1
        cve_count = int(cve_data.get(vendor, 0))
        cisa_count = int(cisa_data.get(vendor, 0))
        ransomware_count = int(ransomware_data.get(vendor, 0))

        existing_vendor = Vendor.query.filter_by(name=vendor).first()
        if existing_vendor:
            existing_vendor.cve_count = cve_count
            existing_vendor.cisa_kev_count = cisa_count
            existing_vendor.ransomware_count = ransomware_count
            existing_vendor.danger_score = di
            db.session.commit()
        else:
            new_vendor = Vendor(
                name=vendor,
                cve_count=cve_count,
                cisa_kev_count=cisa_count,
                ransomware_count=ransomware_count,
                danger_score=di
            )
            db.session.add(new_vendor)

    db.session.commit()


def main():
    basedir = os.path.abspath(os.path.dirname(__file__))
    data_dir = os.path.join(basedir, 'data')
    cve_file = os.path.join(data_dir, 'cve_counts.json')
    cisa_file = os.path.join(data_dir, 'cisa_counts.json')
    ransomware_file = os.path.join(data_dir, 'ransomware_actors_counts.json')
    populate_database(cve_file, cisa_file, ransomware_file)

if __name__ == '__main__':
    with app.app_context():
        main()
