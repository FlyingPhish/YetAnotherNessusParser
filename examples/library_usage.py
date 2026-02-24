#!/usr/bin/env python3
"""
YAPP Library Usage Examples
Concise examples for common use cases
"""

from pathlib import Path

# Example files
NESSUS_FILE = "input/Merged Report.nessus" 
NMAP_FILE = "input/nmap-detailed.xml"
OUTPUT_DIR = "examples/output/"

def basic_parsing():
    """Basic file parsing - auto-detects file type"""
    print("📄 Basic Parsing")
    
    from yapp import process_file
    
    # Auto-detect file type and parse
    nessus_results = process_file(NESSUS_FILE)
    nmap_results = process_file(NMAP_FILE)
    
    # Access parsed data
    nessus_data = nessus_results['parsed']
    nmap_data = nmap_results['parsed']
    
    print(f"Nessus: {len(nessus_data['vulnerabilities'])} vulnerabilities")
    print(f"Nmap: {nmap_data['stats']['services']['total']} services")
    
    return nessus_results, nmap_results

def parsing_with_output():
    """Parse and write files to disk"""
    print("\n💾 Parsing with File Output")
    
    from yapp import process_file
    
    # Parse and automatically write JSON files
    results = process_file(NESSUS_FILE, output_dir=OUTPUT_DIR)
    
    print(f"Parsed {len(results['parsed']['vulnerabilities'])} vulnerabilities")
    print(f"Files written to: {OUTPUT_DIR}")

def nessus_consolidation():
    """Nessus consolidation and API formatting"""
    print("\n🔧 Nessus Consolidation + API")
    
    from yapp import process_file
    
    # Full Nessus pipeline
    results = process_file(
        NESSUS_FILE,
        consolidate=True,
        api_format=True,
        entity_limit=10,
        output_dir=OUTPUT_DIR
    )
    
    # Access results
    parsed = results['parsed']
    consolidated = results.get('consolidated')
    api_data = results.get('api_ready')
    
    print(f"Original vulnerabilities: {len(parsed['vulnerabilities'])}")
    
    if consolidated:
        categories = len(consolidated['consolidated_vulnerabilities'])
        print(f"Consolidated into: {categories} categories")
    
    if api_data:
        print(f"API findings generated: {len(api_data)}")
        
        # Show entity limiting in action
        csv_refs = sum(1 for f in api_data if 'replaceMe' in f['affected_entities'])
        print(f"Findings with entity limit applied: {csv_refs}")

def nmap_processing():
    """Nmap processing with filtering and flat JSON"""
    print("\n🗺️  Nmap Processing")
    
    from yapp import process_file
    
    # Basic Nmap parsing
    results = process_file(NMAP_FILE, port_status="open")
    nmap_data = results['parsed']
    
    open_ports = nmap_data['stats']['ports']['by_status'].get('open', 0)
    print(f"Open ports found: {open_ports}")
    
    # Flat JSON for legacy tool compatibility
    flat_results = process_file(NMAP_FILE, flat_json=True, output_dir=OUTPUT_DIR)
    flat_data = flat_results['flat_json']
    
    print(f"Flat JSON records: {len(flat_data)}")
    print(f"Sample record: {flat_data[0]['ip']}:{flat_data[0]['port']} - {flat_data[0]['service']}")

def working_with_data():
    """Examples of accessing and working with parsed data"""
    print("\n📊 Working with Data")
    
    from yapp import process_file
    
    # Parse Nessus file
    results = process_file(NESSUS_FILE, consolidate=True)
    
    parsed = results['parsed']
    consolidated = results.get('consolidated')
    
    # Access statistics
    stats = parsed['stats']
    print(f"Scan duration: {parsed['context']['scan_duration']}")
    print(f"Critical vulnerabilities: {stats['vulnerabilities']['by_severity']['Critical']}")
    
    # Find critical vulnerabilities
    critical_vulns = [
        vuln for vuln in parsed['vulnerabilities'].values() 
        if vuln['severity'] >= 4
    ]
    print(f"Critical vulnerability details: {len(critical_vulns)} found")
    
    # Work with consolidated data
    if consolidated:
        for rule_name, rule_data in consolidated['consolidated_vulnerabilities'].items():
            affected_services = len(rule_data.get('affected_services', {}))
            print(f"  {rule_data['title']}: {affected_services} affected services")

def direct_parser_usage():
    """Using individual parser classes directly"""
    print("\n🔧 Direct Parser Usage")
    
    from yapp import NessusParser, NmapParser, VulnerabilityConsolidator, APIFormatter
    
    # Direct Nessus parsing
    nessus_parser = NessusParser(NESSUS_FILE)
    nessus_data = nessus_parser.parse()
    
    # Direct Nmap parsing
    nmap_parser = NmapParser(NMAP_FILE)
    nmap_data = nmap_parser.parse(port_status_filter="open")
    nmap_flat = nmap_parser.parse_to_flat_json(port_status_filter="open")
    
    print(f"Nessus vulnerabilities: {len(nessus_data['vulnerabilities'])}")
    print(f"Nmap services: {nmap_data['stats']['services']['total']}")
    print(f"Nmap flat records: {len(nmap_flat)}")
    
    # Manual consolidation and API formatting
    consolidator = VulnerabilityConsolidator()
    consolidated = consolidator.consolidate(nessus_data)
    
    if consolidated:
        formatter = APIFormatter(entity_limit=5)
        api_data = formatter.format_for_api(consolidated)
        print(f"API findings: {len(api_data) if api_data else 0}")

def data_source_processing():
    """Parse raw XML from memory using process_data() — no file path required.

    process_data() mirrors the full process_file() pipeline but accepts a raw
    XML string instead of a file path. Use this when scan data arrives from
    any non-filesystem source: a database column, an API response, a message
    queue payload, an S3 object, etc.
    """
    print("\n🗃️  Data Source Processing (in-memory XML)")

    from yapp import process_data

    # Simulate receiving XML from a data source by reading the file into a
    # string first. In a real integration this string would come from your
    # DB driver / HTTP response / message broker — no temp file needed.
    xml_string = Path(NESSUS_FILE).read_text(encoding='utf-8')

    # file_type must be given explicitly — there is no filename to
    # auto-detect from, so 'nessus' or 'nmap' must be specified.
    results = process_data(
        xml_data=xml_string,
        file_type='nessus',
        consolidate=True,
    )

    parsed = results['parsed']
    consolidated = results.get('consolidated')

    print(f"Parsed {len(parsed['vulnerabilities'])} plugins from in-memory XML")
    print(f"Hosts found: {parsed['stats']['hosts']['total']}")

    if consolidated:
        n = len(consolidated['consolidated_vulnerabilities'])
        print(f"Consolidated into {n} finding(s) — entirely in memory, no files written")

    # process_data() has no output_dir parameter by design.
    # To persist results, pass the returned dict to write_results_to_files()
    # (see single_file_output() below) or serialise it yourself with json.dump().
    return results


def single_file_output():
    """Write all outputs into one combined JSON file — equivalent to CLI -sf flag.

    process_file() calls write_results_to_files() internally but never sets
    single_file=True (the parameter isn't exposed on process_file). To get
    -sf behaviour from the library, skip output_dir on the parse call and
    drive write_results_to_files() yourself.
    """
    print("\n📦 Single-File Output (-sf / --single-file)")

    from yapp import process_file
    from yapp.utils.file_utils import write_results_to_files

    # Run the full pipeline without output_dir so nothing is written yet.
    # Equivalent to: yapp parse -i ... -c -a
    results = process_file(
        NESSUS_FILE,
        consolidate=True,
        api_format=True,
        entity_limit=10,
    )

    # write_results_to_files with single_file=True packs parsed +
    # consolidated + api into one <name>_Combined.json instead of three
    # separate files. This matches: yapp parse -i ... -c -a -sf
    write_status = write_results_to_files(
        results=results,
        input_file=NESSUS_FILE,
        output_dir=OUTPUT_DIR,
        single_file=True,
    )

    written = [k for k, ok in write_status.items() if ok]
    failed = [k for k, ok in write_status.items() if not ok]

    print(f"Sections in combined file: {written}")
    if failed:
        print(f"Failed to write: {failed}")
    print(f"Output: {OUTPUT_DIR}*_Combined.json")


def error_handling():
    """Error handling examples"""
    print("\n🛡️  Error Handling")
    
    from yapp import process_file, ConsolidationError, FormatterError
    
    try:
        results = process_file("nonexistent.nessus", consolidate=True, api_format=True)
    except FileNotFoundError:
        print("✅ Correctly caught missing file")
    
    try:
        results = process_file(NESSUS_FILE, consolidate=True, api_format=True, entity_limit=0)
    except (FormatterError, ValueError) as e:
        print(f"✅ Correctly caught invalid entity limit: {e}")

def batch_processing():
    """Process multiple files"""
    print("\n🔄 Batch Processing")
    
    from yapp import process_file
    
    # Find and process all files
    input_dir = Path("input/")
    nessus_files = list(input_dir.glob("*.nessus"))
    xml_files = list(input_dir.glob("*.xml"))
    
    all_results = {}
    
    for file_path in nessus_files + xml_files:
        try:
            results = process_file(str(file_path))
            all_results[file_path.name] = results
            print(f"✅ Processed {file_path.name}")
        except Exception as e:
            print(f"❌ Failed {file_path.name}: {e}")
    
    # Aggregate statistics
    total_vulns = sum(
        len(result['parsed'].get('vulnerabilities', {})) 
        for result in all_results.values()
        if result['file_type'] == 'nessus'
    )
    
    total_services = sum(
        result['parsed']['stats']['services']['total']
        for result in all_results.values()
        if result['file_type'] == 'nmap'
    )
    
    print(f"Total vulnerabilities: {total_vulns}")
    print(f"Total services: {total_services}")

def main():
    """Run all examples"""
    print("🚀 YAPP Library Usage Examples\n")
    
    # Create output directory
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    
    # Run examples
    examples = [
        basic_parsing,
        parsing_with_output,
        nessus_consolidation,
        nmap_processing,
        working_with_data,
        direct_parser_usage,
        data_source_processing,
        single_file_output,
        error_handling,
        batch_processing
    ]
    
    for example in examples:
        try:
            example()
        except Exception as e:
            print(f"❌ {example.__name__} failed: {e}")
    
    # Show created files
    output_path = Path(OUTPUT_DIR)
    if output_path.exists():
        files = list(output_path.glob("*.json"))
        print(f"\n📁 Files created: {len(files)}")
        for file in sorted(files):
            print(f"  - {file.name}")

if __name__ == "__main__":
    main()