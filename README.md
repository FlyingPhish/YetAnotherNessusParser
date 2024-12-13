# YetAnotherNessusParser

Yet another bloody python-based Nessus parser. My intentions are to create one Py-based Nessus parser to rule them all whilst being modular, efficent and easy to contribute to. This tool works without nessus-file-reader as its not my cup of tea to develop with.

This tool parses .Nessus XML files into structured JSON and Py formats. This tool provides a clean, efficient way to process Nessus vulnerability scan results with detailed host and vulnerability information.

![image](https://github.com/user-attachments/assets/dd1c249c-7dc8-4b37-a011-e6aa3da2b00f)


## Features

- Parse Nessus XML files into structured JSON
- Track unique vulnerabilities globally and per host
- Identify unique IPs and FQDNs in the scan
- Map discovered ports to hosts
- Detailed vulnerability information including CVE, CVSS scores, and affected systems
- Modular design for easy extension

## To-Do
- [x] Create the dammed thing
- [x] Obligatory ASCII art banner for the haters (it isn't a proper tool without one)
- [x] Make it pretty 👉👈
- [ ] Capture all vulnerability information such as CWE and etc
- [ ] Capture all scan information (context)
- [ ] Print more stats on the Nessus file
- [ ] Create .txt output for all CVEs, CWEs, Stats and other
- [ ] Write to XLSX
- [ ] Expand XLSX functionality to include tabs for various things such as all vulns, host info, scan info, grouped plugins
- [ ] Send JSON object to user-specified URL with cookies and headers

## Project Structure

```
.
├── config/             # Configuration files
├── input/             # Input directory for Nessus files
├── modules/           # Core functionality modules
│   ├── __init__.py
│   ├── cli.py        # CLI argument handling
│   ├── file_utils.py # File operations
│   ├── json_utils.py # JSON operations
│   ├── logger.py     # Logging configuration
│   └── nessus.py     # Nessus parsing logic
├── output/           # Output directory for JSON files
├── nessusParser.py   # Main script
├── README.md
└── requirements.txt
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/FlyingPhish/YetAnotherNessusParser && cd YetAnotherNessusParser
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows
```

3. Install requirements:
```bash
pip install -r requirements.txt
```

## Usage

Basic usage:
```bash
python nessusParser.py -n input/your_scan.nessus
```

All available options:
```bash
python nessusParser.py -h
```

Arguments:
- `-n, --nessus-file`: Path to input Nessus XML file (required)
- `-of, --output-folder`: Output folder path (default: ./output)
- `-on, --output-name`: Output file name (default: timestamp_<original-name>_Parsed_Nessus.json)

## Output Format

The tool generates a JSON file with the following structure:

```json
{
  "scan_info": {
    "policy_name": "string",
    "scan_date": "string"
  },
  "host_summary": {
    "number_of_unique_ips": "integer",
    "number_of_unique_fqdns": "integer",
    "number_of_unique_vulns_per_host_per_severity": {
      "host_ip": {
        "Critical": "integer",
        "High": "integer",
        "Medium": "integer",
        "Low": "integer",
        "None": "integer"
      }
    },
    "total_unique_vulns": {
      "Critical": "integer",
      "High": "integer",
      "Medium": "integer",
      "Low": "integer",
      "None": "integer"
    },
    "discovered_ports": ["string"],
    "mapped_ports": {
      "host_ip": ["string"]
    }
  },
  "vulnerabilities": {
    "vulnerability_name": {
      "plugin_id": "string",
      "severity": "int",
      "risk_factor": "string",
      "cvss3_base_score": "int",
      "description": "string",
      "solution": "string",
      "plugin_output": "string",
      "cve": ["string"],
      "references": ["string"],
      "affected_ips": ["string"],
      "affected_fqdns": ["string"], (IP - FQDN)
      "ports": ["string"] (IP - protocol/port)
    }
  }
}
```

## Development

The project follows a modular structure for easy maintenance and extension. Key components:

- `nessusParser.py`: Main entry point and orchestration
- `modules/nessus.py`: Core parsing logic
- `modules/cli.py`: Command line interface handling
- `modules/file_utils.py`: File operations
- `modules/json_utils.py`: JSON handling
- `modules/logger.py`: Logging configuration

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
