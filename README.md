# YAPP - Yet Another Pentest Parser

![External Dependencies](/.github/badges/dependencies.svg)
![Py](/.github/badges/python.svg)

> **One parser to rule them all**

**A powerful Python library and CLI tool for parsing and processing multiple pentesting tool outputs.**

YAPP parses Nessus, Nmap, and BloodHound data into actionable, exportable results. V7 adds a serverless Active Directory operator TUI for prioritized attack paths, privilege exposures, local-admin access, and owned-user analysis—without requiring Neo4j or a BloodHound server.

## 🎯 Why YAPP Exists 
The pentesting industry has a multi-faceted tooling problem (CAPDEV). Most businesses treat capabilities development as an afterthought - they'd rather hire more people to combat performance and resource issues, rather than fix their piss-poor workflows and capabiltiies.

- **Why?** 💰C.R.E.A.M.💰
    - Unbilled consultant = cost to business
        - This is a bad mindset as business teaches us that you need to spend money to make money.
- **Result?**
    - Consultants working unpaid overtime because basic data processing eats half their day
    - Delays, lots of them. These delays then cause a snowball effect where the next engagement is impacted.
    - Cutting corners to meet deadlines.
    - Burnout & general negative vibes.

<img width="536" height="470" alt="image" src="https://github.com/user-attachments/assets/a0f96d93-f908-42f6-85a3-deed0b37c6a5" />

## ✨ Features

### 🔧 **Multi-Tool Support**
- **Nessus XML**: Full vulnerability parsing with consolidation and API formatting
- **Nmap XML**: Service discovery with port filtering, flat JSON output, and a comparison spreadsheet between two scans
- **BloodHound ZIP**: Offline AD analysis, bounded attack paths, privilege exposures, and reporting
- **Extensible Framework**: Easy to add new parsers following established patterns
- **Auto-Detection**: Automatically identifies file types

### 🖥️ **Dual Interface Design**
- **CLI Tool**: Beautiful command-line interface with colored output and tool-specific options
- **TUI Mode**: Operator-first Nessus triage and BloodHound AD investigation (`yapp tui`)
- **Python Library**: Clean programmatic API for integration into your projects
- **In-Memory Processing**: Parse raw XML strings directly — no filesystem required (ideal for DB/API integration via `process_data()`)
- **Serverless AD Analysis**: No Neo4j or BloodHound server; Textual, Kuzu, and OpenPyXL ship as package dependencies

### 📊 **Advanced Nessus Processing**
- Parse Nessus XML files into structured JSON/Python dictionaries
- Advanced consolidation engine with smart vulnerability grouping
- Plugin output pattern matching and filtering
- Rule-based vulnerability categorization
- API-ready output formatting with entity limiting
- **Inline Excel report generation** (`-x` flag) — no more two-step workflow
- **Combined single-file output** (`-sf` flag) — all selected outputs in one JSON

### 🗺️ **Comprehensive Nmap Support**
- Parse Nmap XML into structured format with service details
- Port status filtering (open, closed, filtered)
- Flat JSON output for legacy tool compatibility
- Service enumeration and script output capture
- Compare two Nmap XML files and output differences into spreadsheet

### 🩸 **Active Directory / BloodHound**
- Load BloodHound ZIP collections directly; no database or web server required
- Prioritized, bounded routes to high-value objectives with exact relationship evidence
- Privilege Exposure queue for broad administrative membership, privileged-object control, and local-admin fan-out
- Assumed-owned users from the CLI, files, or the TUI, with fast in-session recomputation
- Bounded node pivots, persistent triage/bookmarks, collection-gap warnings, and JSON/API/Excel exports

### 🎯 **Intelligence & Analytics**
- Track vulnerabilities globally and per host (Nessus)
- Comprehensive statistics and metrics for both tools
- Multiple FQDN support per host
- Detailed vulnerability information (CVE, CVSS, affected systems)
- Human-readable output with plugin/service names
- **Consolidation rule logging -- easily debug consolidation rules by seeing what hasn't matched and why**

### ⚡ **Performance**
**Benchmark Results (Nessus):**
- **File Size**: 118 MB Nessus XML (1005 hosts, 214 findings, 17 remediations)
- **Processing Time**: 9.18 seconds total (5.76s processing + 0.45s I/O)
- **Throughput**: ~13 MB/second (total) / ~20 MB/second (processing only)
- **Memory Efficient**: Low memory footprint with streaming parser
- **Includes**: Full parsing + consolidation engine + API formatting + JSON output (3 files)

*Tested on: WSL2 (Debian) on Windows host*

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

### For Programmatic Usage
```bash
# In your virtual environment
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

```
usage: yapp [-h] [--version] {parse,ad,excel,compare,tui} ...

YAPP - Swiss Army Knife for Pentester File Processing

positional arguments:
  {parse,ad,excel,compare,tui}  Available commands
    parse                Parse and process pentesting files (Nessus/Nmap/JSON)
    ad                   Analyse a BloodHound ZIP collection without a server
    excel                Generate Excel report from YAPP JSON output
    compare              Compare two Nmap XML scans
    tui                  Launch Nessus triage or BloodHound AD operator TUI

options:
  -h, --help       show this help message and exit
  --version        show program's version number and exit
```

### 🖥️ Command Line Interface - Parse
```
yapp parse -h

options:
  -h, --help            show this help message and exit
  -i, --input-file INPUT_FILE
                        Path to input file (Nessus .nessus, Nmap .xml, Consolidated JSON)
  -t, --file-type {auto,nessus,nmap,consolidated_json}
                        Input file type (default: auto-detect)
  -of, --output-folder OUTPUT_FOLDER
                        Output folder path (default: ./output)
  -on, --output-name OUTPUT_NAME
                        Output base name (default: timestamp_<original-name>)
  --no-output           Skip writing files, only display results

Output options:
  -sf, --single-file    Write all selected outputs into one combined JSON file
                        instead of separate files

Nessus options:
  -c, --consolidate     Generate consolidated findings file
  -a, --api-output      Generate API-ready JSON (requires --consolidate)
  -r, --rules-file RULES_FILE
                        Custom consolidation rules file
  -el, --entity-limit ENTITY_LIMIT
                        Max entities per API finding
  --log-exclusions      Enable detailed exclusion logging

Nmap options:
  -s, --port-status {all,open,closed,filtered}
                        Filter by port status (default: all)
  -fj, --flat-json      Generate flat JSON format

Excel options:
  -x, --excel           Also generate Excel report (Nessus: requires -c;
                        or consolidated JSON input)
```

### 🖥️ Command Line Interface - Excel
```
yapp excel -h

options:
  -h, --help            show this help message and exit
  -i, --input-file INPUT_FILE
                        Path to YAPP JSON file (consolidated, combined, or parsed)
  -of, --output-folder OUTPUT_FOLDER
                        Output folder path (default: ./output)
  -on, --output-name OUTPUT_NAME
                        Custom output filename (without extension)
```

### 🖥️ Command Line Interface - Compare
```
yapp compare -h

options:
  -h, --help            show this help message and exit
  -ff, --first-file FIRST_FILE
                        Path to first Nmap XML file
  -lf, --last-file LAST_FILE
                        Path to second Nmap XML file
  -of, --output-folder OUTPUT_FOLDER
                        Output folder path (default: ./output)
  -on, --output-name OUTPUT_NAME
                        Custom output filename (without extension)
```

### 🩸 Command Line Interface - Active Directory
```bash
# Batch analysis and reporting
yapp ad -i bloodhound.zip --paths --owned-users cracked-users.txt -a -x

# Interactive operator workflow (ZIP auto-detected)
yapp tui -i bloodhound.zip --owned-users cracked-users.txt
```

The TUI opens on a prioritized mission view. Press `Enter` to inspect a route, `v` for privilege exposures, and `o` to update assumed-owned users. See [TUI Usage](yapp/docs/TUI%20Usage.md) for the full workflow, terminology, controls, safety model, and bounded-view behavior.

Programmatic users can call `analyze_bloodhound()` directly and receive a JSON-ready report without writing files. See [Library Usage](yapp/docs/Library%20Usage.md#bloodhound--active-directory-processing) for owned-user paths, policy controls, API mapping, Excel output, and error handling.

## 🔬 Nessus Consolidation Engine
The consolidation engine intelligently groups related vulnerabilities, reducing noise and improving vulnerability management efficiency.

![Consolidation Example](https://github.com/user-attachments/assets/8fc1f210-12d3-48ba-a651-dc9c3ee24048)

### Features:
- **Smart Pattern Matching**: Regex patterns for vulnerability names and plugin output
- **Plugin Output Filtering**: Search actual Nessus plugin output content
- **Flexible Grouping**: Group by IP, port, service, or custom criteria
- **Rule-Based Configuration**: JSON rules for different vulnerability types
- **Advanced Logic**: AND/OR pattern matching, exclusion rules
- **Entity Limiting**: Control API output size with configurable entity limits

### Common Consolidation Rules:
- **Outdated Software**: Group software with version update patterns
- **Certificate Issues**: Consolidate SSL/TLS certificate problems
- **Weak Encryption**: Group protocol and cipher vulnerabilities
- **JavaScript Libraries**: Separate web application library issues
- **Operating System**: Group OS-specific updates and patches

## 📊 Excel Report Generation
Transform consolidated vulnerability data into structured Excel workbooks for easy analysis and validation.

<img width="689" height="555" alt="Excel Output CLI" src="https://github.com/user-attachments/assets/4c5b380d-4e0d-4c0a-b3e7-ce957fcc14de" />


### Features:
- **Matrix Layout**: One worksheet per vulnerability with Yes/No plugin indicators
- **Service-Level Detail**: Each row shows FQDN, IP, Port, and which plugins affected it
- **Consolidation Validation**: Quickly verify which plugins were grouped together
- **Analyst-Friendly Format**: Familiar spreadsheet format for review and sign-off
- **Consistent Naming**: Output filename follows the unified `{base}_Report.xlsx` convention

### Workflow:

**Option A — Inline (single command):**
```bash
yapp parse -i scan.nessus -c -x          # Parse, consolidate, and generate Excel in one shot
yapp parse -i scan.nessus -c -a -x       # Full pipeline with API output + Excel
yapp parse -i scan.nessus -c -a -x -sf   # Everything above, combined into one JSON + Excel
```

**Option B — Standalone (from existing JSON):**
```bash
yapp excel -i scan_Consolidated.json      # From a consolidated JSON file
yapp excel -i scan_Combined.json          # From a combined JSON file (extracts consolidated data)
```

## 🔬 Nessus Consolidation Engine + API Formatter
You can use `-a` or `--api-output`, which transforms the results of your consolidation rules into a basic JSON structure that can be used with a reporting engine to turn Nessus results into findings within your pentest report engine. The output has been designed to work with my custom API for [Ghostwriter](https://github.com/GhostManager/Ghostwriter). (DM me on Twatter (x) if you want more info on this)

![API Formatter](https://github.com/user-attachments/assets/e4c66d26-6251-401e-814b-127fdb924ede)

## 🔬 Nmap Parser
You can see the proper output in the below sections

![Nmap Analysis CLI Output](https://github.com/user-attachments/assets/37bc4dae-85b4-4a7a-80d0-9597e91337dd)

### 📊 Nmap Result Comparisons

<img width="628" height="534" alt="image" src="https://github.com/user-attachments/assets/91804d3e-f976-4f8e-9efd-c296c5ca5db9" />


## 📋 Output Formats

### Nessus Standard Parsed Output
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

### Nessus Consolidated Output (with -c flag)
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

### Nmap Standard Parsed Output
```json
{
  "context": {
    "scanner": "nmap",
    "scanner_version": "7.97",
    "scan_start": "string",
    "scan_end": "string",
    "scan_duration": "5m 30s",
    "scan_type": "syn"
  },
  "stats": {
    "hosts": {
      "total": 50,
      "unique_ips": 50,
      "by_status": {"up": 45, "down": 5}
    },
    "ports": {
      "by_status": {
        "open": 1203
      },
      "by_port": {
        "tcp/135": 50,
      }
    },
    "services": {
      "total": 150,
      "by_service": {"http": 25, "https": 20, "ssh": 30}
    }
  },
  "hosts": {
    "1": {
      "ip": "192.168.1.100",
      "hostname": "server.example.com",
      "status": "up",
      "ports": {
        "tcp/443": {
          "port_id": "443",
          "protocol": "tcp",
          "status": "open",
          "service_name": "https",
          "service_details": {
            "product": "Microsoft Windows RPC",
            "method": "probed",
            "conf": "10",
            "combined_info": "Microsoft Windows RPC"
          },
          "script_output": {}
        }
      },
      "port_summary": {
        "open": 15,
        "closed": 0,
        "filtered": 0
      }
    }
  },
  "services": {
    "service_1": {
      "host_ip": "10.10.0.12",
      "host_hostname": "",
      "port": "tcp/135",
      "port_status": "open",
      "service_name": "msrpc",
      "service_details": {
        "product": "Microsoft Windows RPC",
        "method": "probed",
        "conf": "10",
        "combined_info": "Microsoft Windows RPC"
      },
      "script_output": {}
    }
  }
}
```

### Nmap Flat JSON Output (Legacy Compatibility)
```json
[
  {
    "fqdn": "example.com",
    "ip": "192.168.1.1",
    "port": "TCP/80",
    "port_status": "open",
    "service": "http",
    "detailed_service_info": {
      "product": "nginx",
      "version": "1.18.0",
      "combined_info": "nginx 1.18.0",
      "extrainfo": "Ubuntu",
      "method": "probed",
      "conf": "10"
    },
    "script_output": {
      "http-server-header": "nginx/1.18.0 (Ubuntu)",
      "http-title": "Welcome to nginx!"
    }
  },
]
```

### Nessus API-Ready Output (with Entity Limiting)
```json
[
  {
    "type": "stock",
    "finding_id": 999,
    "affected_entities": "<p>192.168.1.100:443<br />server.example.com</p>"
  },
  {
    "type": "stock", 
    "finding_id": 1001,
    "affected_entities": "<p>Please refer to external document named 'replaceMe'.csv</p>" // This is what happens when you use -el and the result is > than your int
  }
]
```

### Combined Single-File Output (with -sf flag)
When using `-sf`, all selected outputs are combined into a single JSON file. Only the outputs you selected are included as top-level keys:

```json
{
  "parsed": { ... },
  "consolidated": { ... },
  "api": [ ... ]
}
```

**Examples:**
- `yapp parse -i scan.nessus -sf` → `{"parsed": {...}}`
- `yapp parse -i scan.nessus -c -sf` → `{"parsed": {...}, "consolidated": {...}}`
- `yapp parse -i scan.nessus -c -a -sf` → `{"parsed": {...}, "consolidated": {...}, "api": [...]}`

### Output File Naming

YAPP uses consistent naming conventions for all output files:

| Flag(s) | Default name | With `-on my_scan` |
|---|---|---|
| *(base)* | `{timestamp}_{input}_Parsed.json` | `my_scan_Parsed.json` |
| `-c` | `{timestamp}_{input}_Consolidated.json` | `my_scan_Consolidated.json` |
| `-a` | `{timestamp}_{input}_API.json` | `my_scan_API.json` |
| `-fj` | `{timestamp}_{input}_Flat.json` | `my_scan_Flat.json` |
| `-sf` | `{timestamp}_{input}_Combined.json` | `my_scan_Combined.json` |
| `-x` | `{timestamp}_{input}_Report.xlsx` | `my_scan_Report.xlsx` |

The `-on` flag sets the **base name** — YAPP always appends the appropriate suffix and extension automatically. Passing `my_scan`, `my_scan.json`, or `my_scan.xlsx` all resolve to the same base `my_scan`.

## 🏗️ Project Structure

```
yapp/
├── __init__.py              # Main package API
├── cli.py                   # CLI interface
├── core/                    # Core processing modules
│   ├── __init__.py
│   ├── processor.py         # Main processing pipeline (process_file + process_data)
│   ├── nessus_parser.py     # Nessus XML parsing
│   ├── nmap_comparator.py   # Nmap comparison
│   ├── nmap_parser.py       # Nmap XML parsing
│   ├── excel_formatter.py   # Excel logic
│   ├── consolidator.py      # Vulnerability consolidation
│   └── formatter.py         # API output formatting
├── utils/                   # Utility modules
│   ├── __init__.py
│   ├── file_utils.py        # File operations & detection
│   ├── json_utils.py        # JSON handling
│   ├── display.py           # CLI output formatting
│   └── logger.py            # Logging utilities
└── config/                  # Configuration
    ├── __init__.py
    ├── default_rules.json    # Default consolidation rules
    └── consolidation_README.md
```

### 🐍 Python Library

```python
from yapp import process_file

# Auto-detect and parse any supported file
results = process_file('scan.nessus')  # or scan.xml

# Nessus with full pipeline (including inline Excel)
nessus_results = process_file(
    'scan.nessus',
    consolidate=True,
    api_format=True,
    excel_format=True,
    entity_limit=10
)

# Nmap with filtering and flat JSON
nmap_results = process_file(
    'scan.xml',
    port_status='open',
    flat_json=True
)

# Access parsed data
nessus_data = nessus_results['parsed']
consolidated = nessus_results.get('consolidated')
api_ready = nessus_results.get('api_ready')

nmap_data = nmap_results['parsed']
flat_json = nmap_results.get('flat_json')
```

#### Processing raw XML from memory

For integration with databases, APIs, or message queues — no filesystem required:

```python
from yapp import process_data

# Nessus XML from a database column
xml_str = db.fetch_xml(scan_id)
results = process_data(xml_str, file_type='nessus', consolidate=True, api_format=True)

# Nmap XML from an HTTP response
results = process_data(response.text, file_type='nmap', port_status='open')
```

#### Using individual parser classes directly

```python
from yapp import NessusParser, NmapParser, VulnerabilityConsolidator, APIFormatter

# From file
nessus_parser = NessusParser('scan.nessus')
nessus_data = nessus_parser.parse()

# From raw XML string (e.g. pulled from a DB)
nessus_parser = NessusParser(xml_data=raw_xml_string)
nessus_data = nessus_parser.parse()

nmap_parser = NmapParser(xml_data=nmap_xml_string)
nmap_data = nmap_parser.parse(port_status_filter='open')

# Manual consolidation + API formatting
consolidator = VulnerabilityConsolidator()
consolidated = consolidator.consolidate(nessus_data)

formatter = APIFormatter(entity_limit=5)
api_data = formatter.format_for_api(consolidated)
```

For comprehensive examples, see [Library Usage Examples](examples/library_usage.py), [Library Documentation](yapp/docs/Library%20Usage.md), and [TUI Usage](yapp/docs/TUI%20Usage.md).


## 🔧 Framework Extension

YAPP is designed as an extensible framework. Adding support for new pentesting tools follows a consistent pattern:

1. Create parser class in `core/your_tool_parser.py`
2. Update file detection in `utils/file_utils.py`
3. Add tool support to `core/processor.py`
4. Update CLI arguments and display functions
5. Export in module `__init__.py` files

See [Module Expansion Guide](yapp/docs/Module%20Expansion.md) for detailed instructions.

## 📈 Roadmap

### Supported Tools:
- ✅ **Nessus** (.nessus XML files)
- ✅ **Nmap** (.xml XML files)
- ✅ **BloodHound** (ZIP collections; offline analysis and operator TUI)
- 🔄 **Burp**: Branch created with core burp functionality - pending
- 🔄 **Framework ready for**: Masscan, Nuclei, OpenVAS, and more

### Current Version Features:
- [X] V7 offline BloodHound analysis and operator-led AD TUI
- [X] Prioritized attack paths, privilege exposures, and local-admin access
- [X] Owned-user recomputation, node pivots, triage, bookmarks, and AD exports
- [X] Make the damned tool
- [X] Obligatory ASCII art banner for the haters (it isn't a proper tool without one)
- [X] Make it pretty 👉👈
- [X] Multi-tool parsing framework
- [X] Nessus parsing with consolidation
- [X] Nmap parsing with flat JSON support
- [X] Auto file type detection
- [X] Entity limiting for API output
- [X] Extensible architecture
- [X] Excel/XLSX output formats
- [X] Verbose consolidation reporting
- [x] Intergrate comparison functionality from [Nmap-Analysis](https://github.com/FlyingPhish/Nmap-Analysis)
- [X] In-memory XML processing (`process_data()` / `xml_data=` parameter) for DB/API integration
- [X] Combined single-file JSON output (`-sf` / `--single-file`)
- [X] Inline Excel generation from parse pipeline (`-x` / `--excel`)
- [X] Standalone `yapp excel` subcommand for post-hoc Excel generation
- [X] Consistent output file naming (fixed `-on` extension handling)

### Future Enhancements:
- [ ] Enhanced type annotations
- [ ] Additional tool parsers
- [ ] Advanced filtering and querying
- [ ] Intergrate functionality from [NessCIS](https://github.com/FlyingPhish/NessCIS)
- [ ] (Maybe) AI reporting (finding + executive summary/consultants comments) using [Fabric](https://github.com/danielmiessler/fabric) or something similar.

## 🤝 Contributing

We welcome contributions! See [Module Expansion Guide](yapp/docs/Module%20Expansion.md) for adding new parsers.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Follow existing patterns for consistency
4. Add tests and documentation
5. Submit a Pull Request

### Key Design Principles:
- **KISS**: Keep implementations simple and readable
- **DRY**: Modular, reusable components
- **Calculated Dependencies**: OpenPyXL for workbooks, Textual for the TUI, and Kuzu for graph analysis
- **Extensible**: Framework-based architecture for easy expansion

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built for the pentesting and security community. 
- Inspired by the need for a clean, dependency-free, multi-tool parser framework. We know that most companies skimp on internal R&D.

---

**YAPP**: *Yet Another Pentest Parser* - A unified framework for parsing pentesting tool outputs! 🔧🐍✨
