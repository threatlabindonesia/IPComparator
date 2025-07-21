import os
import re
import argparse
import pandas as pd
from tqdm import tqdm
from multiprocessing import Pool, cpu_count
from functools import partial
import warnings
import openpyxl
import psutil
import time

warnings.filterwarnings("ignore")

BANNER = """
----------------------------------------------------------------------------
             IP Matching Tool for Origin and Folder Files (Fast Edition)
 Description: Optimized version for millions of rows with fast matching using 
              set operations and efficient memory handling.
 Author: Afif Hidayatullah
 Organization: ITSEC Asia
----------------------------------------------------------------------------
"""

def monitor_memory():
    process = psutil.Process()
    mem_info = process.memory_info()
    return mem_info.rss / (1024 ** 2)

def read_file_auto(file_path, chunksize=50000):
    try:
        if file_path.endswith('.csv'):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                sample = f.readline()
                delimiter = ';' if sample.count(';') > sample.count(',') else ','
            return pd.read_csv(file_path, sep=delimiter, dtype=str, chunksize=chunksize, low_memory=False)
        elif file_path.endswith('.xlsx'):
            wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
            ws = wb.active
            rows = list(ws.iter_rows(values_only=True))
            header = rows[0]
            chunks = []
            for i in range(1, len(rows), chunksize):
                chunk = pd.DataFrame(rows[i:i+chunksize], columns=header)
                chunks.append(chunk.astype(str))
            wb.close()
            return chunks if chunks else [pd.DataFrame()]
        else:
            print(f"[!] Unsupported file format: {file_path}")
            return [pd.DataFrame()]
    except Exception as e:
        print(f"[!] Error reading {file_path}: {str(e)}")
        return [pd.DataFrame()]

def extract_ips_chunk(chunk):
    if chunk.empty:
        return set()
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    text = chunk.astype(str).agg(' '.join, axis=1)
    return set(ip for text in text for ip in ip_pattern.findall(text))

def process_file(file_path, origin_ips, include_threat_actor):
    file_name = os.path.basename(file_path)
    matches = []
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    try:
        for chunk in read_file_auto(file_path):
            if not isinstance(chunk, pd.DataFrame) or chunk.empty:
                continue
            chunk = chunk.fillna('')
            feed_text = chunk.astype(str).agg(' '.join, axis=1)
            for idx, line in enumerate(feed_text):
                found_ips = ip_pattern.findall(line)
                matched_ips = [ip for ip in found_ips if ip in origin_ips]
                if matched_ips:
                    ip = matched_ips[0]
                    actor = ''
                    if include_threat_actor:
                        possible_actor_cols = ['Associated Actors', 'Threat Actor', 'Threat Actor Name', 'Actor Name']
                        actor_col = next((col for col in chunk.columns if col.strip().lower() in [x.lower() for x in possible_actor_cols]), None)
                        actor = chunk.at[idx, actor_col] if actor_col and actor_col in chunk.columns else 'Unknown'
                    matches.append({'Matched IP': ip, 'Source File': file_name, 'Threat Actor': actor})
    except Exception as e:
        print(f"[!] Error processing {file_name}: {str(e)}")
    return matches

def build_ip_index(chunk, ip_pattern, chunk_start_idx):
    ip_index = {}
    text = chunk.astype(str).agg(' '.join, axis=1)
    for idx, line in enumerate(text):
        for ip in ip_pattern.findall(line):
            ip_index.setdefault(ip, []).append(idx + chunk_start_idx)
    return ip_index

def compare_ips_fast(origin_path, folder_path, output_file, include_threat_actor=False):
    print(BANNER)
    print(f"[+] Start time: {time.strftime('%H:%M:%S')}")
    print("[+] Loading origin IPs...")

    origin_ips = set()
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    for chunk in read_file_auto(origin_path):
        if isinstance(chunk, pd.DataFrame):
            chunk = chunk.fillna('')
            origin_ips.update(extract_ips_chunk(chunk))

    print(f"[+] Found {len(origin_ips)} unique IPs in origin file (Memory: {monitor_memory():.2f} MB)")

    origin_df_chunks = []
    chunksize = 50000
    for chunk in read_file_auto(origin_path, chunksize=chunksize):
        if isinstance(chunk, pd.DataFrame):
            chunk = chunk.fillna('')
            chunk['Matched IP'] = ''
            chunk['Source File'] = ''
            chunk['Status'] = ''
            if include_threat_actor:
                chunk['Threat Actor'] = ''
            origin_df_chunks.append(chunk)

    print("[+] Scanning folder files...")
    folder_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith(('.csv', '.xlsx'))]
    max_processes = min(cpu_count(), 4)
    pool = Pool(processes=max_processes)
    process_func = partial(process_file, origin_ips=origin_ips, include_threat_actor=include_threat_actor)
    all_matches = []
    for matches in tqdm(pool.imap_unordered(process_func, folder_files), total=len(folder_files), desc="Matching files"):
        all_matches.extend(matches)
    pool.close()
    pool.join()

    print(f"[+] Matching complete (Memory: {monitor_memory():.2f} MB)")
    print("[+] Building IP index for origin DataFrame...")

    ip_index = {}
    for chunk_idx, chunk in enumerate(tqdm(origin_df_chunks, desc="Indexing chunks")):
        chunk_start_idx = chunk_idx * chunksize
        chunk_index = build_ip_index(chunk, ip_pattern, chunk_start_idx)
        for ip, indices in chunk_index.items():
            ip_index.setdefault(ip, []).extend(indices)

    print(f"[+] IP index built (Memory: {monitor_memory():.2f} MB)")
    print("[+] Updating DataFrame with matches...")

    origin_df = pd.concat(origin_df_chunks, ignore_index=True)
    server_ip_cols = [col for col in origin_df.columns if re.match(r'server[_\s]?ip[_\s]?addr', col, re.IGNORECASE)]
    client_ip_cols = [col for col in origin_df.columns if re.match(r'client[_\s]?ip[_\s]?addr', col, re.IGNORECASE)]

    for match in tqdm(all_matches, desc="Applying matches"):
        ip = match['Matched IP']
        if ip not in ip_index:
            continue

        indices = ip_index[ip]
        col_matched_ip = origin_df.columns.get_loc('Matched IP')
        col_source_file = origin_df.columns.get_loc('Source File')
        col_status = origin_df.columns.get_loc('Status')
        col_threat_actor = origin_df.columns.get_loc('Threat Actor') if include_threat_actor else None

        for idx in indices:
            origin_df.iat[idx, col_matched_ip] = ip
            origin_df.iat[idx, col_source_file] = match['Source File']
            if include_threat_actor:
                origin_df.iat[idx, col_threat_actor] = match['Threat Actor']

            row = origin_df.iloc[idx]
            for col in server_ip_cols:
                if str(row[col]) == ip:
                    origin_df.iat[idx, col_status] = 'compromise'
            for col in client_ip_cols:
                if str(row[col]) == ip:
                    origin_df.iat[idx, col_status] = 'targeted'

    result = origin_df[origin_df['Matched IP'] != '']
    print(f"\n[+] Saving results to {output_file} (Memory: {monitor_memory():.2f} MB)")
    if result.empty:
        print("[!] No matching IPs found.")
    else:
        if output_file.endswith('.csv'):
            result.to_csv(output_file, index=False, chunksize=chunksize)
        else:
            result.to_excel(output_file, index=False, engine='xlsxwriter')
        print(f"[\u2713] Done. Results saved to {output_file}")

    print(f"[+] End time: {time.strftime('%H:%M:%S')}")

def main():
    parser = argparse.ArgumentParser(description="Fast IP matching tool for large datasets.")
    parser.add_argument("--origin-path", required=True)
    parser.add_argument("--folder-path", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--TA", action="store_true")
    args = parser.parse_args()

    compare_ips_fast(args.origin_path, args.folder_path, args.output, include_threat_actor=args.TA)

if __name__ == "__main__":
    main()
