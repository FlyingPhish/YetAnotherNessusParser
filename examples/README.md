#!/usr/bin/env python3
"""
YANP Quick Reference - Common Use Cases
Copy and paste these examples for quick implementation
"""

# =============================================================================
# BASIC PARSING
# =============================================================================

# 📄 Parse to file
from yanp import process_nessus_file
results = process_nessus_file("scan.nessus", output_dir="./output")
parsed_data = results['parsed']

# 🧠 Parse to memory only
from yanp import process_nessus_file
results = process_nessus_file("scan.nessus")
parsed_data = results['parsed']
print(f"Found {len(parsed_data['vulnerabilities'])} vulnerabilities")

# 🔧 Parse with individual classes
from yanp import NessusParser
parser = NessusParser("scan.nessus")
parsed_data = parser.parse()

# =============================================================================
# PARSING + CONSOLIDATION
# =============================================================================

# 📄 Parse + consolidate to files
from yanp import process_nessus_file
results = process_nessus_file("scan.nessus", consolidate=True, output_dir="./output")
parsed_data = results['parsed']
consolidated_data = results.get('consolidated')

# 🧠 Parse + consolidate to memory only
from yanp import process_nessus_file
results = process_nessus_file("scan.nessus", consolidate=True)
consolidated_data = results.get('consolidated')
if consolidated_data:
    categories = len(consolidated_data['consolidated_vulnerabilities'])
    print(f"Consolidated into {categories} categories")

# 🔧 Parse + consolidate with individual classes
from yanp import NessusParser, VulnerabilityConsolidator
parser = NessusParser("scan.nessus")
parsed_data = parser.parse()

consolidator = VulnerabilityConsolidator()  # Default rules
consolidated_data = consolidator.consolidate(parsed_data)

# =============================================================================
# FULL PIPELINE (PARSE + CONSOLIDATE + API FORMAT)
# =============================================================================

# 📄 Full pipeline to files
from yanp import process_nessus_file
results = process_nessus_file(
    "scan.nessus", 
    consolidate=True, 
    api_format=True, 
    output_dir="./output"
)
api_data = results.get('api_ready')

# 🧠 Full pipeline to memory only
from yanp import process_nessus_file
results = process_nessus_file("scan.nessus", consolidate=True, api_format=True)
api_data = results.get('api_ready')
if api_data:
    print(f"Generated {len(api_data)} API findings")

# 🔧 Full pipeline with individual classes
from yanp import NessusParser, VulnerabilityConsolidator, APIFormatter

parser = NessusParser("scan.nessus")
parsed_data = parser.parse()

consolidator = VulnerabilityConsolidator()
consolidated_data = consolidator.consolidate(parsed_data)

if consolidated_data:
    formatter = APIFormatter()
    api_data = formatter.format_for_api(consolidated_data)

# =============================================================================
# ADVANCED USAGE
# =============================================================================

# 🎛️ Custom rules file
from yanp import process_nessus_file
results = process_nessus_file(
    "scan.nessus", 
    consolidate=True, 
    rules_file="my_custom_rules.json"
)

# 📝 Custom output names
from yanp import process_nessus_file
results = process_nessus_file(
    "scan.nessus", 
    consolidate=True, 
    api_format=True,
    output_dir="./output",
    custom_output_name="my_scan_results.json"
)
# Creates:
# - my_scan_results.json
# - my_scan_results_Consolidated_Findings.json  
# - my_scan_results_API_Ready.json

# 🛡️ Error handling
from yanp import process_nessus_file, ConsolidationError, FormatterError

try:
    results = process_nessus_file("scan.nessus", consolidate=True, api_format=True)
except FileNotFoundError:
    print("Nessus file not found")
except ConsolidationError as e:
    print(f"Consolidation failed: {e}")
except FormatterError as e:
    print(f"API formatting failed: {e}")

# =============================================================================
# WORKING WITH THE DATA
# =============================================================================

# 📊 Access parsed data
from yanp import process_nessus_file
results = process_nessus_file("scan.nessus")
data = results['parsed']

# Get statistics
stats = data['stats']
print(f"Hosts: {stats['hosts']['total']}")
print(f"Vulnerabilities: {stats['vulnerabilities']['total']}")
print(f"Severity breakdown: {stats['vulnerabilities']['by_severity']}")

# Get vulnerabilities
vulnerabilities = data['vulnerabilities']
for plugin_id, vuln in vulnerabilities.items():
    if vuln['severity'] >= 4:  # Critical
        print(f"Critical: {vuln['name']}")

# 📋 Access consolidated data
results = process_nessus_file("scan.nessus", consolidate=True)
if results.get('consolidated'):
    consolidated = results['consolidated']
    
    # Get metadata
    metadata = consolidated['consolidation_metadata']
    print(f"Original plugins: {metadata['original_plugins_count']}")
    print(f"Consolidated: {metadata['consolidated_count']}")
    
    # Get consolidated vulnerabilities
    vulns = consolidated['consolidated_vulnerabilities']
    for rule_name, rule_data in vulns.items():
        print(f"Category: {rule_data['title']}")
        print(f"Severity: {rule_data['severity']}")
        print(f"Affected services: {len(rule_data['affected_services'])}")

# 🎯 Access API data
results = process_nessus_file("scan.nessus", consolidate=True, api_format=True)
if results.get('api_ready'):
    api_data = results['api_ready']
    
    for finding in api_data:
        finding_id = finding['finding_id']
        entities = finding['affected_entities']
        entity_count = entities.count('<br />') + 1 if entities else 0
        print(f"Finding {finding_id}: {entity_count} affected entities")

# =============================================================================
# BATCH PROCESSING
# =============================================================================

# 🔄 Process multiple files
from yanp import process_nessus_file
from yanp.utils import find_nessus_files

nessus_files = find_nessus_files("./scans", recursive=True)
all_results = {}

for nessus_file in nessus_files:
    try:
        results = process_nessus_file(str(nessus_file), consolidate=True)
        all_results[nessus_file.name] = results
        print(f"✅ Processed {nessus_file.name}")
    except Exception as e:
        print(f"❌ Failed to process {nessus_file.name}: {e}")

# 📈 Aggregate statistics from multiple scans
total_vulns = 0
for filename, results in all_results.items():
    if results and 'parsed' in results:
        vuln_count = len(results['parsed']['vulnerabilities'])
        total_vulns += vuln_count
        print(f"{filename}: {vuln_count} vulnerabilities")

print(f"Total vulnerabilities across all scans: {total_vulns}")

# =============================================================================
# FILE I/O UTILITIES
# =============================================================================

# 💾 Manual file writing
from yanp import NessusParser
from yanp.utils import write_json_output

parser = NessusParser("scan.nessus")
data = parser.parse()

# Write to custom location
success = write_json_output(data, "./custom/output/scan_data.json")
print(f"File write: {'✅ Success' if success else '❌ Failed'}")

# 📂 Manual file output for all types
from yanp.utils import write_results_to_files

results = process_nessus_file("scan.nessus", consolidate=True, api_format=True)
write_status = write_results_to_files(
    results, 
    "scan.nessus", 
    "./output",
    custom_output_name="custom_name.json"
)

for file_type, success in write_status.items():
    print(f"{file_type}: {'✅ Success' if success else '❌ Failed'}")