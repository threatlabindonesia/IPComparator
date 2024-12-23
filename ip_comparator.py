BANNER = """
----------------------------------------------------------------------------
             IP Matching Tool for Origin and Folder Files

 Description: This tool compares IPs in an origin file (CSV/XLSX) against 
              files in a folder (CSV/XLSX). Matches are logged with details 
              from the origin file, matched IPs, and optionally their 
              corresponding Threat Actor information if --TA is specified.

 Author: Afif Hidayatullah
 Organization: ITSEC Asia
----------------------------------------------------------------------------
"""

import os
import re
import pandas as pd
import argparse
from tqdm import tqdm  # For progress bar


def find_threat_actor_column(data):
    """
    Dynamically find the Threat Actor column in the DataFrame.
    Looks for variations like 'Threat Actor', 'Associated Actors', 'Actor Name'.
    """
    for col in data.columns:
        if re.match(r'(threat\s*actor|associated\s*actors|actor\s*name)', col.strip(), re.IGNORECASE):
            return col
    return None


def extract_ips_with_threat_actor(data, ip_set, include_threat_actor=False):
    """
    Extract matching IPs and their associated Threat Actors from the data.
    """
    matches = {}
    threat_actor_col = find_threat_actor_column(data) if include_threat_actor else None

    for _, row in data.iterrows():
        row_str = ' '.join(row.astype(str))  # Combine all columns into a single string
        ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', row_str)
        for ip in ips:
            if ip in ip_set:
                threat_actor = row.get(threat_actor_col, "Unknown") if threat_actor_col else None
                matches[ip] = threat_actor if include_threat_actor else None
    return matches


def compare_ips(origin_path, folder_path, output_file, include_threat_actor=False):
    """
    Compare IPs from the origin file with IPs in files from the specified folder.
    Optionally fetch Threat Actor information dynamically if --TA is provided.
    """
    print("Extracting IPs from the origin file...")
    origin_data = pd.read_excel(origin_path) if origin_path.endswith('.xlsx') else pd.read_csv(origin_path)
    origin_data['Matched IP'] = None
    origin_data['Source File'] = None
    if include_threat_actor:
        origin_data['Threat Actor'] = None

    # Extract IPs from the origin file
    origin_ips = origin_data.apply(lambda row: re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ' '.join(row.astype(str))), axis=1).explode().dropna().unique()

    print("\nProcessing folder files...")
    folder_files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f)) and f.lower().endswith(('.csv', '.xlsx'))]

    for file_name in tqdm(folder_files, desc="Matching IPs", unit="file"):
        file_path = os.path.join(folder_path, file_name)
        try:
            data = pd.read_excel(file_path) if file_path.endswith('.xlsx') else pd.read_csv(file_path)
        except Exception as e:
            print(f"Error reading file {file_name}: {e}")
            continue

        # Extract matching IPs and optionally Threat Actors
        folder_matches = extract_ips_with_threat_actor(data, set(origin_ips), include_threat_actor)

        # Update the origin data with matching details
        for index, row in origin_data.iterrows():
            row_ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', ' '.join(row.astype(str)))
            for ip in row_ips:
                if ip in folder_matches:
                    origin_data.at[index, 'Matched IP'] = ip
                    origin_data.at[index, 'Source File'] = file_name
                    if include_threat_actor:
                        origin_data.at[index, 'Threat Actor'] = folder_matches[ip]

    # Filter rows with matches
    matched_data = origin_data.dropna(subset=['Matched IP'])

    print("\nSaving results...")
    if not matched_data.empty:
        if output_file.lower().endswith('.csv'):
            matched_data.to_csv(output_file, index=False)
        elif output_file.lower().endswith('.xlsx'):
            matched_data.to_excel(output_file, index=False)
        else:
            raise ValueError("Output file must have a .csv or .xlsx extension")
        print(f"Results saved to {output_file}")
    else:
        print("No matching IPs found.")


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="Compare IPs from an origin file with multiple files in a folder.")
    parser.add_argument("--origin-path", required=True, help="Path to the origin file (CSV or XLSX).")
    parser.add_argument("--folder-path", required=True, help="Path to the folder containing CSV or XLSX files.")
    parser.add_argument("--output", required=True, help="Path to the output file (CSV or XLSX).")
    parser.add_argument("--TA", action="store_true", help="Include Threat Actor information if available.")
    args = parser.parse_args()

    compare_ips(args.origin_path, args.folder_path, args.output, include_threat_actor=args.TA)


if __name__ == "__main__":
    main()
