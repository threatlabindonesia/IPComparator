# IP Matching Tool for Origin and Folder Files

## Description
The **IP Matching Tool** is a Python-based utility designed to compare IP addresses from an origin file (`CSV/XLSX`) against files in a folder (`CSV/XLSX`). It logs matching details, including IPs, source files, and optionally associated Threat Actor information, making it an essential tool for cybersecurity analysts.

---

## Features
- **Dynamic Threat Actor Detection:** Automatically identifies columns containing threat actor information.
- **Flexible Input Formats:** Supports both `.csv` and `.xlsx` files.
- **Comprehensive Output:** Saves results with matched IPs, source files, and optionally, threat actor details.
- **Progress Tracking:** Includes a progress bar for processing large folders.

---

## Author
- **Afif Hidayatullah**
- **Organization:** ITSEC Asia
- **LinkedIn:** [Afif Hidayatullah](https://www.linkedin.com/in/afif-hidayatullah)

---

## Requirements
Ensure the following dependencies are installed before running the tool:

- Python 3.7 or higher
- Required libraries:
  ```bash
  pandas
  argparse
  tqdm
  psutil
  openpyxl  # For handling Excel files
  ```

To install the dependencies, use:
```bash
pip install pandas argparse tqdm openpyxl
```

---

## Installation
1. Clone the repository or download the script:
   ```bash
   git clone https://github.com/threatlabindonesia/IPComparator.git
   cd IPComparator
   ```

2. Install the required libraries:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the script directly from the terminal.

---

## Usage
The script can be run with the following command:
```bash
python ip_comparator.py --origin-path <path_to_origin_file> --folder-path <path_to_folder> --output <output_file_path> [--TA]
```

### Arguments:
- `--origin-path`: Path to the origin file (CSV or XLSX).
- `--folder-path`: Path to the folder containing CSV or XLSX files to match against.
- `--output`: Path to the output file (CSV or XLSX).
- `--TA`: (Optional) Include Threat Actor information if available.

### Example:
```bash
python ip_comparator.py --origin-path data/origin.xlsx --folder-path data/folder --output results/matched_ips.xlsx --TA
```

---

## Example Output

If matches are found, the tool generates a file like this:

| **Matched IP** | **Source File**    | **Threat Actor** |
|-----------------|--------------------|-------------------|
| 192.168.1.1     | log1.csv          | ThreatGroup APT1 |
| 10.0.0.5        | report.xlsx       | Unknown           |
| 172.16.0.3      | incidents.csv     | ThreatGroup XYZ   |

If no matches are found:
```text
No matching IPs found.
```

---

## Notes
- Ensure the origin and folder files are properly formatted (CSV/XLSX).
- Large datasets may take longer to process; use the progress bar for tracking.

---

## Feedback
If you have any questions or feedback, feel free to contact me on [LinkedIn](https://www.linkedin.com/in/afif-hidayatullah).
