# YAPP - Yet Another Pentest Parser

![No External Dependencies](/.github/badges/no-dependencies.svg)
![Py](/.github/badges/python.svg)

**A powerful Python library and CLI tool for parsing and processing Nessus vulnerability scan results.**

YAPP is a comprehensive solution for parsing Nessus XML files into structured JSON, with advanced consolidation capabilities and both programmatic and command-line interfaces. Built with modularity, efficiency, and ease of use in mind.

![YAPP CLI Banner](https://github.com/user-attachments/assets/263b181d-d8ae-4ede-b91e-a76537bc8aaf)

## ✨ Features

### 🔧 **Dual Interface Design**
- **CLI Tool**: Beautiful command-line interface with colored output
- **Python Library**: Clean programmatic API for integration into your projects
- **No External Dependencies**: Pure Python implementation

### 📊 **Advanced Processing**
- Parse Nessus XML files into structured JSON/Python dictionaries
- Advanced consolidation engine with smart vulnerability grouping
- Plugin output pattern matching and filtering
- Rule-based vulnerability categorization
- API-ready output formatting for integration

### 🎯 **Intelligence & Analytics**
- Track vulnerabilities globally and per host
- Comprehensive statistics and metrics
- Multiple FQDN support per host
- Detailed vulnerability information (CVE, CVSS, affected systems)
- Human-readable output with plugin names

### ⚡ **Performance**
**Benchmark Results:**
- **File Size**: 118 MB Nessus XML (1005 hosts, 214 findings, 17 remediations)
- **Processing Time**: 9.18 seconds total (5.76s processing + 0.45s I/O)
- **Throughput**: ~13 MB/second (total) / ~20 MB/second (processing only)
- **Memory Efficient**: Low memory footprint with streaming parser
- **Includes**: Full parsing + consolidation engine + API formatting + JSON output (3 files)

*Tested on: WSL2 (Debian) on Windows host*

## To-Do
- [X] Create the dammed thing
- [X] Obligatory ASCII art banner for the haters (it isn't a proper tool without one)
- [X] Make it pretty 👉👈
- [X] Capture all scan (context) & vulnerability information such as CWE and etc
- [X] Print more stats on the Nessus file
- [X] Nessus finding consolidation engine
- [X] Consolidation rule file
- [X] Consolidation rule validation
- [X] Consolidation rule guidance
- [X] Plugin output pattern matching and filtering
- [X] Human-readable consolidated output with plugin names
- [X] Consolidation rules can now have internal_vulnerability_id, which is used to match consolidated rules to findings within your vulnerability stock/reporting software
- [X] New arg -a (--api-output) that uses internal stock id to generate a JSON object to use with my GhostWriter fork (SQL API to insert/attach blank/stock findings to a report)
- [X] Transform into proper Python library
- [X] CLI and programmatic interfaces
- [X] New -el --entity-limit for formatter, which replaces the affected_entities value with 'Please refer to external document named replaceMe.csv' if the affected entities for consolidated findings is greater than you limit you provide
- [ ] Verbose consolidation info (to show what was missed and why)
- [ ] Ensure proper typing on JSON object 🤓 (priority pls)
- [ ] Create output module to output to text and xslx files
- [ ] Expand XLSX functionality to include tabs for various things such as all vulns, host info, scan info, grouped plugins

## 🚀 Installation

### For CLI Usage Only
```bash
# Install globally with pipx (recommended for CLI-only usage)
git clone https://github.com/FlyingPhish/YetAnotherPentestParser && cd YetAnotherPentestParser
pipx install .
```
OR
```bash
pipx install git+https://github.com/FlyingPhish/YetAnotherPentestParser.git
# pipx install git+https://github.com/FlyingPhish/YetAnotherPentestParser.git@branch
```
### For Programmatic Usage (using within your py projects)
```bash
# activate your virtual env
pip install git+https://github.com/FlyingPhish/YetAnotherPentestParser.git
# pip install git+https://github.com/FlyingPhish/YetAnotherPentestParser.git@branch
```
### Upgrading
```bash
# When installed using pipx
pipx upgrade yapp

# When installed using pip
pip install git+https://github.com/FlyingPhish/YetAnotherPentestParser.git --force-reinstall
```
## 💡 Usage

### 🖥️ Command Line Interface

**CLI Arguments:**
- `-n, --nessus-file`: Path to Nessus XML file (required)
- `-of, --output-folder`: Output directory (default: ./output)
- `-on, --output-name`: Custom output filename
- `-c, --consolidate`: Enable vulnerability consolidation
- `-a, --api-output`: Generate API-ready format (requires -c)
- `-r, --rules-file`: Custom consolidation rules file
- `--no-output`: Display results only, don't write files
- `--version`: Show version information

#### Basic parsing:
```bash
yapp -n input/scan.nessus
```

#### With consolidation:
```bash
yapp -n input/scan.nessus -c
```

#### Full pipeline with custom naming:
```bash
yapp -n input/scan.nessus -of ./reports -on my_results.json -c -a
```

#### Display results without saving files:
```bash
yapp -n input/scan.nessus --no-output -c
```

### 🐍 Python Library
Checkout [Library Usage Examples](examples/library_usage.py) and [Library README](yapp/docs/Library%20Usage.md.md)

## 🏗️ Project Structure

```
yapp/
├── __init__.py              # Main package API
├── cli.py                   # CLI interface
├── core/                    # Core processing modules
│   ├── __init__.py
│   ├── nessus_parser.py     # Nessus XML parsing
│   ├── consolidator.py      # Vulnerability consolidation
│   └── formatter.py         # API output formatting
├── utils/                   # Utility modules
│   ├── __init__.py
│   ├── file_utils.py        # File operations
│   ├── json_utils.py        # JSON handling
│   └── logger.py            # Logging utilities
└── config/                  # Configuration
    ├── __init__.py
    ├── default_rules.json    # Default consolidation rules
    └── consolidation_README.md
```

## 🔬 Consolidation Engine

The consolidation engine intelligently groups related vulnerabilities, reducing noise and improving vulnerability management efficiency.

![Consolidation Example](https://github.com/user-attachments/assets/2f8a0d80-5de7-414b-8569-de936a92c892)

### Features:
- **Smart Pattern Matching**: Regex patterns for vulnerability names and plugin output
- **Plugin Output Filtering**: Search actual Nessus plugin output content
- **Flexible Grouping**: Group by IP, port, service, or custom criteria
- **Rule-Based Configuration**: JSON rules for different vulnerability types
- **Advanced Logic**: AND/OR pattern matching, exclusion rules

### Common Consolidation Rules:
- **Outdated Software**: Group software with version update patterns
- **Certificate Issues**: Consolidate SSL/TLS certificate problems
- **Weak Encryption**: Group protocol and cipher vulnerabilities
- **JavaScript Libraries**: Separate web application library issues
- **Operating System**: Group OS-specific updates and patches

## 📋 Output Formats

### Standard Parsed Output
```json
{
  "context": {
    "scan_id": "string",
    "scan_start": "DD-MM-YYYY HH:MM:SS",
    "scan_duration": "H:MM:SS",
    "policy_name": "string"
  },
  "stats": {
    "hosts": {
      "total": 100,
      "credentialed_checks": 95,
      "multi_fqdn_hosts": 10
    },
    "vulnerabilities": {
      "total": 500,
      "by_severity": {
        "Critical": 5,
        "High": 25,
        "Medium": 150,
        "Low": 200,
        "None": 120
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

### API-Ready Output (with API formatting)
```json
[
  {
    "type": "stock",
    "finding_id": 999,
    "affected_entities": "<p>192.168.1.100:443<br />server.example.com</p>"
  }
]
```



## 🤝 Contributing
Read [Module Expansion Guide](yapp/docs/Module%20Expansion.md) 
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following the project structure
4. Add tests for new functionality
5. Update documentation
6. Submit a Pull Request

### Key Design Principles:
- **KISS**: Keep implementations simple and readable
- **DRY**: Modular, reusable components
- **No External Dependencies**: Pure Python implementation
- **Extensible**: Easy to add new features and rules

### Contributing Guidelines:
- Follow existing code style (Black + isort)
- Add type hints for new functions
- Update documentation
- Ensure backward compatibility
- Keep the "no external dependencies" principle

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built for the security community
- Inspired by the need for a clean, dependency-free Nessus parser

---

**YAPP**: *Same shit, different parser* - but now as a proper Python library! 🐍✨
