# YAPP Library Usage Guide

Quick reference for common YAPP use cases. Copy and paste these examples for immediate implementation.

## Basic Parsing

### Auto-detect file type
```python
from yapp import process_file

# Automatically detects Nessus or Nmap
results = process_file("scan.nessus")
results = process_file("scan.xml")

# Access parsed data
data = results['parsed']
print(f"File type: {results['file_type']}")
```

### Parse to memory only
```python
from yapp import process_file

results = process_file("scan.nessus")
parsed_data = results['parsed']
print(f"Found {len(parsed_data['vulnerabilities'])} vulnerabilities")
```

### Parse with file output
```python
from yapp import process_file

results = process_file("scan.nessus", output_dir="./output")
# Creates timestamped JSON files in ./output/
```

## Nessus Processing

### Basic Nessus parsing
```python
from yapp import process_file

results = process_file("scan.nessus")
data = results['parsed']

# Access statistics
stats = data['stats']
print(f"Hosts: {stats['hosts']['total']}")
print(f"Vulnerabilities: {stats['vulnerabilities']['total']}")
print(f"Critical: {stats['vulnerabilities']['by_severity']['Critical']}")
```

### Nessus with consolidation
```python
from yapp import process_file

results = process_file("scan.nessus", consolidate=True)
consolidated = results.get('consolidated')

if consolidated:
    metadata = consolidated['consolidation_metadata']
    print(f"Reduced {metadata['consolidated_count']} vulnerabilities")
```

### Full Nessus pipeline (parse + consolidate + API format)
```python
from yapp import process_file

results = process_file(
    "scan.nessus", 
    consolidate=True, 
    api_format=True,
    entity_limit=10,
    output_dir="./output"
)

api_data = results.get('api_ready')
if api_data:
    print(f"Generated {len(api_data)} API findings")
```

### Custom consolidation rules
```python
from yapp import process_file

results = process_file(
    "scan.nessus", 
    consolidate=True,
    rules_file="custom_rules.json"
)
```

## Nmap Processing

### Basic Nmap parsing
```python
from yapp import process_file

results = process_file("scan.xml")
data = results['parsed']

# Access statistics
stats = data['stats']
print(f"Hosts: {stats['hosts']['total']}")
print(f"Services: {stats['services']['total']}")
```

### Nmap with port filtering
```python
from yapp import process_file

# Only process open ports
results = process_file("scan.xml", port_status="open")
data = results['parsed']
print(f"Open ports found: {stats['ports']['by_status']['open']}")
```

### Nmap with flat JSON output (legacy compatibility)
```python
from yapp import process_file

results = process_file("scan.xml", flat_json=True)
flat_data = results['flat_json']

# Each record is one port on one host
for record in flat_data:
    print(f"{record['ip']}:{record['port']} - {record['service']}")
```

## Working with Individual Classes

### Direct parser usage
```python
from yapp import NessusParser, NmapParser

# Nessus
nessus_parser = NessusParser("scan.nessus")
nessus_data = nessus_parser.parse()

# Nmap
nmap_parser = NmapParser("scan.xml")
nmap_data = nmap_parser.parse(port_status_filter="open")
```

### Manual consolidation and formatting
```python
from yapp import NessusParser, VulnerabilityConsolidator, APIFormatter

# Parse
parser = NessusParser("scan.nessus")
parsed_data = parser.parse()

# Consolidate
consolidator = VulnerabilityConsolidator()
consolidated_data = consolidator.consolidate(parsed_data)

# Format for API
if consolidated_data:
    formatter = APIFormatter(entity_limit=5)
    api_data = formatter.format_for_api(consolidated_data)
```

## Data Access Patterns

### Nessus data structure
```python
results = process_file("scan.nessus")
data = results['parsed']

# Context information
context = data['context']
print(f"Scan duration: {context['scan_duration']}")

# Host information
hosts = data['hosts']
for host_id, host_info in hosts.items():
    print(f"Host {host_info['ip']}: {len(host_info['ports'])} ports")

# Vulnerability information
vulnerabilities = data['vulnerabilities']
for plugin_id, vuln in vulnerabilities.items():
    if vuln['severity'] >= 4:  # Critical
        print(f"Critical: {vuln['name']}")
        for host_id, host_data in vuln['affected_hosts'].items():
            print(f"  Affects: {host_data['ip']}")
```

### Nmap data structure
```python
results = process_file("scan.xml")
data = results['parsed']

# Context information
context = data['context']
print(f"Scanner: {context['scanner']} {context['scanner_version']}")

# Host information
hosts = data['hosts']
for host_id, host_info in hosts.items():
    print(f"Host {host_info['ip']}: {host_info['status']}")

# Service information
services = data['services']
for service_id, service_info in services.items():
    print(f"Service: {service_info['service_name']} on {service_info['host_ip']}")
```

## Error Handling

```python
from yapp import process_file, ConsolidationError, FormatterError

try:
    results = process_file("scan.nessus", consolidate=True, api_format=True)
except FileNotFoundError:
    print("File not found")
except ConsolidationError as e:
    print(f"Consolidation failed: {e}")
except FormatterError as e:
    print(f"API formatting failed: {e}")
except ValueError as e:
    print(f"Unsupported file type: {e}")
```

## Batch Processing

```python
from yapp import process_file
from pathlib import Path

# Process all files in a directory
scan_dir = Path("./scans")
results = {}

for scan_file in scan_dir.glob("*.nessus"):
    try:
        result = process_file(str(scan_file), consolidate=True)
        results[scan_file.name] = result
        print(f"✅ Processed {scan_file.name}")
    except Exception as e:
        print(f"❌ Failed {scan_file.name}: {e}")

# Aggregate statistics
total_vulns = sum(
    len(result['parsed']['vulnerabilities']) 
    for result in results.values()
)
print(f"Total vulnerabilities: {total_vulns}")
```

## File I/O Utilities

### Manual JSON output
```python
from yapp.utils import write_json_output

results = process_file("scan.nessus")
success = write_json_output(results['parsed'], "./custom/output.json")
print(f"Write {'successful' if success else 'failed'}")
```

### Custom file naming
```python
from yapp import process_file

results = process_file(
    "scan.nessus",
    consolidate=True,
    api_format=True,
    output_dir="./output",
    custom_output_name="my_scan.json"
)
# Creates:
# - my_scan.json (main parsed data)
# - my_scan_Consolidated_Findings.json
# - my_scan_API_Ready.json
```

## Advanced Usage

### Custom entity limits for API output
```python
from yapp import process_file

# Limit affected entities per finding to prevent large outputs
results = process_file(
    "scan.nessus",
    consolidate=True,
    api_format=True,
    entity_limit=20
)
```

### Memory-only processing with multiple outputs
```python
from yapp import process_file

results = process_file("scan.nessus", consolidate=True, api_format=True)

# Access all output types
parsed_data = results['parsed']          # Raw parsed data
consolidated = results['consolidated']    # Consolidated findings
api_ready = results['api_ready']         # API-formatted data

# Process each as needed
print(f"Original vulnerabilities: {len(parsed_data['vulnerabilities'])}")
print(f"Consolidated categories: {len(consolidated['consolidated_vulnerabilities'])}")
print(f"API findings: {len(api_ready)}")
```