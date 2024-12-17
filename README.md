# YetAnotherNessusParser

Yet another bloody python-based Nessus parser. My intentions are to create one Py-based Nessus parser to rule them all whilst being modular, efficent and easy to contribute to. This tool doesn't use any external libs (looking at you nessus-file-reader)

This tool parses .Nessus XML files into structured JSON and Py formats. This tool provides a clean, efficient way to process Nessus vulnerability scan results with detailed host and vulnerability information.

![image](https://github.com/user-attachments/assets/5fe9f8a5-fec0-443e-b89a-850ea78d3de2)



## Features

- Parse Nessus XML files into structured JSON
- Track unique vulnerabilities globally and per host
- Identify unique hosts in the scan
- Map discovered ports to hosts
- Provides high-level stats and info
- Detailed vulnerability information including CVE, CVSS scores, and affected systems
- Modular design for easy extension
- No external libs needed
- Py dictionary is the exact same as JSON object

## To-Do
- [X] Create the dammed thing
- [X] Obligatory ASCII art banner for the haters (it isn't a proper tool without one)
- [X] Make it pretty 👉👈
- [X] Capture all vulnerability information such as CWE and etc
- [X] Capture all scan information (context)
- [X] Print more stats on the Nessus file
- [ ] Ensure proper typing on JSON object 🤓 (priority pls)
- [ ] Create .txt output for all CVEs, CWEs, Stats and other
- [ ] Write to XLSX
- [ ] Expand XLSX functionality to include tabs for various things such as all vulns, host info, scan info, grouped plugins
- [ ] Send JSON object to user-specified URL with cookies and headers

## Project Structure

```
.
├── config/           # Configuration files - not used yet
├── input/            # Input directory for Nessus files
├── modules/          # Core functionality modules
│   ├── __init__.py
│   ├── cli.py        # CLI argument handling
│   ├── file_utils.py # File operations
│   ├── json_utils.py # JSON operations
│   ├── logger.py     # Logging configuration
│   └── nessus.py     # Nessus parsing logic
├── output/           # Output directory for JSON files
├── yanp.py           # Main script
├── README.md
└── requirements.txt
```

## Installation

1. Clone the repository:
```bash
git clone https://github.com/FlyingPhish/YetAnotherNessusParser && cd YetAnotherNessusParser
```

2. Done! No external libs needed.
<!-- 2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows
```

3. Install requirements:
```bash
pip install -r requirements.txt
``` -->

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
  "context": {
    "scan_id": "string",
    "scan_name": "string",
    "policy_name": "string",
    "scan_start": "string",
    "scan_end": "string",
    "scan_duration": "string"
  },
  "stats": {
    "hosts": {
      "total": int,
      "total_ips": int,
      "total_fqdns": int,
      "multi_fqdn_hosts": int,
      "credentialed_checks": int
    },
    "ports": {
      "total_discovered": int,
      "list": [
        "string # 445/tcp for example" 
      ],
      "services": {
        "www": int,
        "general": int
      }
    },
    "vulnerabilities": {
      "total": int,
      "by_severity": {
        "Critical": int,
        "High": int,
        "Medium": int,
        "Low": int,
        "None": int
      },
      "by_family": {
        "General": int,
        "Service detection": int,
        "Port scanners": int,
        "Web Servers": int,
        "Misc.": int,
        "Settings": int
      }
    }
  },
  "hosts": {
    "1": {
      "ip": "string",
      "fqdns": [
        "string",
        "string"
      ],
      "os": "string",
      "scan_start": "string",
      "scan_end": "string",
      "credentialed_scan": bool,
      "vulnerabilities": {
        "Critical": int,
        "High": int,
        "Medium": int,
        "Low": int,
        "None": int
      },
      "ports": {
        "443/tcp": {
          "service": "string",
          "vulnerabilities": [
            "string # plugin id"
          ]
        },
        "80/tcp": {
          "service": "string",
          "vulnerabilities": [
            "string # plugin id"
          ]
        }
      }
    }
  },
  "vulnerabilities": {
    "142960": {
      "name": "string",
      "family": "string",
      "severity": int,
      "risk_factor": "string",
      "cvss": {
        "base_score": int,
        "temporal_score": int,
        "vector": "string"
      },
      "cvss3": {
        "base_score": int,
        "temporal_score": int,
        "vector": "string"
      },
      "description": "string",
      "synopsis": "string",
      "solution": "string",
      "see_also": [
        "string"
      ],
      "cve": [],
      "cwe": [],
      "xref": [],
      "affected_hosts": {
        "1": {
          "ip": "string",
          "fqdn": "string",
          "ports": [
            "string # 445/tcp for example" 
          ],
          "plugin_output": "string"
        }
      }
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
