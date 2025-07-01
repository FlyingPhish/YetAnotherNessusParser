# YetAnotherNessusParser
![No External Dependencies](/.github/badges/no-dependencies.svg)
![Py](/.github/badges/python.svg)

Yet another bloody python-based Nessus parser. My intentions are to create one Py-based Nessus parser to rule them all whilst being modular, efficent and easy to contribute to. This tool doesn't use any external libs (looking at you nessus-file-reader)

This tool parses .Nessus XML files into structured JSON and Py formats. This tool provides a clean, efficient way to process Nessus vulnerability scan results with detailed host and vulnerability information, plus an advanced consolidation engine to group related vulnerabilities intelligently.

![image](https://github.com/user-attachments/assets/860c69e9-8e13-4dd7-a6e7-6350f54b0cda)


## Features

- Parse Nessus XML files into structured JSON
- Advanced Consolidation Engine - Group related vulnerabilities using smart rules
- Plugin Output Filtering - Search and match vulnerabilities based on actual plugin output content
- Rule-Based Vulnerability Categorization - Configurable rules for outdated software, weak encryption, certificates, etc.
- Track unique vulnerabilities globally and per host
- Identify unique hosts in the scan
- Map discovered ports to hosts
- Provides high-level stats and info
- Detailed vulnerability information including CVE, CVSS scores, and affected systems
- Human-readable consolidated output with plugin names and structured data
- Modular design for easy extension
- No external libs needed
- Py dictionary is the exact same as JSON object

## Performance

YANP delivers decent performance on large Nessus files:

**Benchmark Results:**
- **File Size**: 118 MB Nessus XML (1005 hosts, 214 findings, 17 remediations)
- **Processing Time**: 5.87 seconds  
- **Throughput**: ~20 MB/second
- **Memory Efficient**: Low memory footprint with streaming parser
- **Includes**: Full parsing + consolidation engine + JSON output

*Tested on: Debian WSL on Windows host*

## To-Do
- [X] Create the dammed thing
- [X] Obligatory ASCII art banner for the haters (it isn't a proper tool without one)
- [X] Make it pretty 👉👈
- [X] Capture all vulnerability information such as CWE and etc
- [X] Capture all scan information (context)
- [X] Print more stats on the Nessus file
- [X] Nessus finding consolidation engine
- [X] Consolidation rule file
- [X] Consolidation rule validation
- [X] Consolidation rule guidance
- [X] Plugin output pattern matching and filtering
- [X] Human-readable consolidated output with plugin names
- [X] Consolidation rules can now have internal_vulnerability_id, which is used to match consolidated rules to findings within your vulnerability stock/reporting software
- [X] Bit of spring cleaning (code)
- [X] New arg -a (--api-output) that uses internal stock id to generate a JSON object to use with my GhostWriter fork (SQL API to insert/attach blank/stock findings to a report)
- [ ] Verbose consolidation info (to show what was missed and why)
- [ ] Ensure proper typing on JSON object 🤓 (priority pls)
- [ ] Create output module to output to text and xslx files
- [ ] Expand XLSX functionality to include tabs for various things such as all vulns, host info, scan info, grouped plugins
- [ ] Send JSON object to user-specified URL with cookies and headers

## Project Structure

```
.
├── config/           # Configuration files
│   ├── consolidation_rules.json    # Consolidation rules configuration
│   └── consolidation_README.md     # Consolidation guide and documentation
├── input/            # Input directory for Nessus files
├── modules/          # Core functionality modules
│   ├── __init__.py
│   ├── cli.py        # CLI argument handling and display
│   ├── consolidation.py  # Vulnerability consolidation engine
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
2. Rename consolidation_rules.json.example -> consolidation_rules.json
3. Done! No external libs needed.

## Usage

### Basic parsing:
```bash
python yanp.py -n input/your_scan.nessus
```

### Parse with vulnerability consolidation:
```bash
python yanp.py -n input/your_scan.nessus -c
```

### Custom output location:
```bash
python yanp.py -n input/your_scan.nessus -of ./reports -on my_scan_results.json -c
```

### All available options:
```bash
python yanp.py -h
```

**Arguments:**
- `-n, --nessus-file`: Path to input Nessus XML file (required)
- `-of, --output-folder`: Output folder path (default: ./output)
- `-on, --output-name`: Output file name (default: timestamp_<original-name>_Parsed_Nessus.json)
- `-c, --consolidate`: Generate consolidated findings file based on rules

## Consolidation Engine

The consolidation engine groups related vulnerabilities into meaningful categories, reducing noise and making vulnerability management more efficient.

### Example Consolidation Output:
![image](https://github.com/user-attachments/assets/2f8a0d80-5de7-414b-8569-de936a92c892)


### Consolidation Features:
- **Smart Pattern Matching**: Uses regex patterns to match vulnerability names and plugin output content
- **Plugin Output Filtering**: Search inside actual Nessus plugin output for version information, error messages, etc.
- **Flexible Grouping**: Group by IP, port, service, or custom criteria
- **Rule-Based**: Configurable JSON rules for different vulnerability types
- **Human-Readable Output**: Plugin names included alongside IDs for better readability
- **Advanced Logic**: AND/OR pattern matching, exclusion rules, family filtering

### Common Use Cases:
- **Outdated Software**: Group all software with "Installed version...Fixed version" patterns
- **Certificate Issues**: Consolidate expired, invalid, and self-signed certificate findings
- **Weak Encryption**: Group TLS/SSL protocol and cipher vulnerabilities
- **JavaScript Libraries**: Separate web application library vulnerabilities
- **Operating System Issues**: Group OS-specific updates and patches

For detailed consolidation rule configuration, see `config/consolidation_README.md`.

## Output Format

### Standard Parsed Output
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
      "list": ["string"],
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
        "Service detection": int
      }
    }
  },
  "hosts": {
    "1": {
      "ip": "string",
      "fqdns": ["string"],
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
          "vulnerabilities": ["string"]
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
        "base_score": float,
        "temporal_score": float,
        "vector": "string"
      },
      "cvss3": {
        "base_score": float,
        "temporal_score": float,
        "vector": "string"
      },
      "description": "string",
      "synopsis": "string",
      "solution": "string",
      "see_also": ["string"],
      "cve": [],
      "cwe": [],
      "xref": [],
      "affected_hosts": {
        "1": {
          "ip": "string",
          "fqdn": "string",
          "ports": ["string"],
          "plugin_output": "string"
        }
      }
    }
  }
}
```

### Consolidated Output (with -c flag)
When using the `-c` flag, an additional consolidated findings file is generated:

```json
{
  "consolidation_metadata": {
    "rules_applied": ["rule_name1", "rule_name2"],
    "original_plugins_count": int,
    "consolidated_count": int,
    "consolidation_timestamp": "string"
  },
  "consolidated_vulnerabilities": {
    "rule_name": {
      "title": "Human-Readable Title",
      "severity": int,
      "risk_factor": "string",
      "cvss": {},
      "cvss3": {},
      "consolidated_plugins": {
        "plugin_id": "Plugin Name"
      },
      "cve": [],
      "cwe": [],
      "solutions": [],
      "affected_services": {
        "192.168.1.100:443": {
          "ip": "string",
          "fqdn": "string", 
          "port": "string",
          "issues_found": [
            {
              "id": "plugin_id",
              "name": "Plugin Name"
            }
          ],
          "plugin_outputs": {
            "plugin_id": {
              "name": "Plugin Name",
              "output": "string"
            }
          }
        }
      }
    }
  }
}
```

## Configuration

### Consolidation Rules
Create custom consolidation rules in `config/consolidation_rules.json`:

```json
{
  "consolidation_rules": [
    {
      "rule_name": "my_custom_rule",
      "title": "My Custom Vulnerability Group",
      "enabled": true,
      "filters": {
        "name_patterns": ["Adobe.*", "Flash.*"],
        "plugin_output_patterns": ["Installed version.*Fixed version"],
        "plugin_output_require_all": false,
        "exclude_plugin_output_patterns": [".*Detection only.*"]
      },
      "grouping_criteria": ["ip", "port"]
    }
  ]
}
```

## Development

The project follows a modular structure for easy maintenance and extension. Key components:

- `yanp.py`: Main entry point and orchestration
- `modules/nessus.py`: Core parsing logic
- `modules/consolidation.py`: Vulnerability consolidation engine with plugin output filtering
- `modules/cli.py`: Command line interface handling and display formatting
- `modules/file_utils.py`: File operations
- `modules/json_utils.py`: JSON handling
- `modules/logger.py`: Logging configuration

### Key Design Principles:
- **KISS (Keep It Simple, Stupid)**: Clean, readable code without over-engineering
- **DRY (Don't Repeat Yourself)**: Modular, reusable components
- **No External Dependencies**: Pure Python implementation
- **Extensible**: Easy to add new consolidation rules and features

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Contributing Guidelines:
- Follow the existing code style and structure
- Add tests for new functionality
- Update documentation for new features
- Ensure all existing functionality continues to work
