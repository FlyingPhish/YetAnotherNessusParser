import argparse
import sys
from pathlib import Path
from typing import Dict, Any, List

from .core.nessus_parser import NessusParser
from .core.nmap_parser import NmapParser
from .core.consolidator import VulnerabilityConsolidator, ConsolidationError
from .core.formatter import APIFormatter, FormatterError
from .utils import setup_logging, write_results_to_files
from .utils.file_utils import ensure_output_directory, detect_file_type

# Get version directly to avoid circular import
try:
    from importlib.metadata import version
    __version__ = version("yapp")
except ImportError:
    __version__ = "ERROR"
except Exception:
    __version__ = "ERROR"

class Colors:
    MAGENTA = '\033[95m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    ORANGE = '\033[38;5;214m'
    BRIGHT = '\033[1m'
    RESET = '\033[0m'

def print_banner(version: str):
    """Print YAPP ASCII art banner"""
    banner = """
▓██   ██▓ ▄▄▄       ██▓███   ██▓███  
 ▒██  ██▒▒████▄    ▓██░  ██▒▓██░  ██▒
  ▒██ ██░▒██  ▀█▄  ▓██░ ██▓▒▓██░ ██▓▒
  ░ ▐██▓░░██▄▄▄▄██ ▒██▄█▓▒ ▒▒██▄█▓▒ ▒
  ░ ██▒▓░ ▓█   ▓██▒▒██▒ ░  ░▒██▒ ░  ░
   ██▒▒▒  ▒▒   ▓▒█░▒▓▒░ ░  ░▒▓▒░ ░  ░
 ▓██ ░▒░   ▒   ▒▒ ░░▒ ░     ░▒ ░     
 ▒ ▒ ░░    ░   ▒   ░░       ░░       
 ░ ░           ░  ░                  
 ░ ░                                 """

    tagline = "Swiss Army Knife for Pentester File Processing"
    author = "By @FlyingPhishy"
    version_text = f"        v{version}"

    print(f"{Colors.GREEN}{Colors.BRIGHT}{banner}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BRIGHT}{version_text}{Colors.RESET}\n")
    print(f"{Colors.YELLOW}{Colors.BRIGHT}{tagline}{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BRIGHT}{author}{Colors.RESET}\n")

def display_summary(parsed_data: dict, file_type: str):
    """Display formatted summary of scan results"""
    if file_type == "nessus":
        display_nessus_summary(parsed_data)
    elif file_type == "nmap":
        display_nmap_summary(parsed_data)

def display_nessus_summary(parsed_data: dict):
    """Display formatted summary of Nessus scan results"""
    stats = parsed_data['stats']
    context = parsed_data['context']

    # Color mappings for risk factors
    risk_colors = {
        'Critical': Colors.MAGENTA + Colors.BRIGHT,
        'High': Colors.RED + Colors.BRIGHT,
        'Medium': '\033[38;5;214m' + Colors.BRIGHT,
        'Low': Colors.YELLOW + Colors.BRIGHT,
        'None': Colors.GREEN
    }

    # Print Summary
    print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.WHITE}{Colors.BRIGHT}NESSUS SCAN SUMMARY{Colors.RESET}")
    print(f"{Colors.CYAN}{'-' * 50}{Colors.RESET}")
    
    # Scan Context
    print(f"{Colors.WHITE}{Colors.BRIGHT}Scan Context:{Colors.RESET}")
    print(f"  • Start Time: {Colors.GREEN}{context['scan_start']}{Colors.RESET}")
    print(f"  • End Time: {Colors.GREEN}{context['scan_end']}{Colors.RESET}")
    print(f"  • Duration: {Colors.GREEN}{context['scan_duration']}{Colors.RESET}")
    print(f"  • Policy: {Colors.GREEN}{context['policy_name']}{Colors.RESET}")
    
    # Asset Information
    print(f"\n{Colors.WHITE}{Colors.BRIGHT}Asset Information:{Colors.RESET}")
    print(f"  • Total Hosts: {Colors.GREEN}{stats['hosts']['total']}{Colors.RESET}")
    print(f"  • Hosts with Multiple FQDNs: {Colors.GREEN}{stats['hosts']['multi_fqdn_hosts']}{Colors.RESET}")
    print(f"  • Unique IPs: {Colors.GREEN}{stats['hosts']['total_ips']}{Colors.RESET}")
    print(f"  • Unique FQDNs: {Colors.GREEN}{stats['hosts']['total_fqdns']}{Colors.RESET}")
    print(f"  • Discovered Ports: {Colors.GREEN}{stats['ports']['total_discovered']}{Colors.RESET}")
    print(f"  • Credentialed Hosts: {Colors.GREEN}{stats['hosts']['credentialed_checks']}{Colors.RESET}")
    
    # Vulnerability Summary
    print(f"\n{Colors.WHITE}{Colors.BRIGHT}Vulnerability Summary:{Colors.RESET}")
    risk_order = ['Critical', 'High', 'Medium', 'Low', 'None']
    
    for risk in risk_order:
        count = stats['vulnerabilities']['by_severity'].get(risk, 0)
        bullet = "•"
        print(f"  {bullet} {risk_colors[risk]}{risk}: {count}{Colors.RESET}")

    # Service Information (only if services exist)
    if stats['ports']['services']:
        print(f"\n{Colors.WHITE}{Colors.BRIGHT}Service Information:{Colors.RESET}")
        for service, count in stats['ports']['services'].items():
            print(f"  • {service}: {Colors.GREEN}{count}{Colors.RESET}")
    
    print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")

def display_nmap_summary(parsed_data: dict):
    """Display formatted summary of Nmap scan results"""
    stats = parsed_data['stats']
    context = parsed_data['context']

    # Print Summary
    print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.WHITE}{Colors.BRIGHT}NMAP SCAN SUMMARY{Colors.RESET}")
    print(f"{Colors.CYAN}{'-' * 50}{Colors.RESET}")
    
    # Scan Context
    print(f"{Colors.WHITE}{Colors.BRIGHT}Scan Context:{Colors.RESET}")
    print(f"  • Scanner: {Colors.GREEN}Nmap {context['scanner_version']}{Colors.RESET}")
    print(f"  • Start Time: {Colors.GREEN}{context['scan_start']}{Colors.RESET}")
    print(f"  • End Time: {Colors.GREEN}{context['scan_end']}{Colors.RESET}")
    print(f"  • Duration: {Colors.GREEN}{context['scan_duration']}{Colors.RESET}")
    print(f"  • Scan Type: {Colors.GREEN}{context['scan_type']}{Colors.RESET}")
    
    # Host Information
    print(f"\n{Colors.WHITE}{Colors.BRIGHT}Host Information:{Colors.RESET}")
    print(f"  • Total Hosts: {Colors.GREEN}{stats['hosts']['total']}{Colors.RESET}")
    print(f"  • Unique IPs: {Colors.GREEN}{stats['hosts']['unique_ips']}{Colors.RESET}")
    print(f"  • Unique Hostnames: {Colors.GREEN}{stats['hosts']['unique_hostnames']}{Colors.RESET}")
    
    # Host Status Breakdown
    if stats['hosts']['by_status']:
        print(f"  • Host Status:")
        for status, count in stats['hosts']['by_status'].items():
            status_color = Colors.GREEN if status == 'up' else Colors.YELLOW
            print(f"    └─ {status_color}{status.title()}: {count}{Colors.RESET}")
    
    # Port Information
    print(f"\n{Colors.WHITE}{Colors.BRIGHT}Port Information:{Colors.RESET}")
    if stats['ports']['by_status']:
        for status, count in stats['ports']['by_status'].items():
            status_color = Colors.GREEN if status == 'open' else Colors.YELLOW if status == 'filtered' else Colors.RED
            print(f"  • {status_color}{status.title()} Ports: {count}{Colors.RESET}")
    
    # Service Information
    print(f"\n{Colors.WHITE}{Colors.BRIGHT}Service Information:{Colors.RESET}")
    print(f"  • Total Services: {Colors.GREEN}{stats['services']['total']}{Colors.RESET}")
    
    if stats['services']['by_service']:
        top_services = sorted(stats['services']['by_service'].items(), key=lambda x: x[1], reverse=True)[:10]
        print(f"  • Top Services:")
        for service, count in top_services:
            print(f"    └─ {Colors.GREEN}{service}: {count}{Colors.RESET}")
    
    print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")

def display_consolidation_summary(consolidated_data: dict):
    """Display formatted consolidation summary matching YAPP aesthetic"""
    if not consolidated_data or not consolidated_data.get('consolidated_vulnerabilities'):
        return
    
    metadata = consolidated_data['consolidation_metadata']
    consolidated_vulns = consolidated_data['consolidated_vulnerabilities']
    
    # Calculate impact metrics
    original_count = metadata['original_plugins_count']
    consolidated_count = len(consolidated_vulns)
    reduction = metadata['consolidated_count']
    final_count = original_count - reduction + consolidated_count
    
    # Print Consolidation Summary
    print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.WHITE}{Colors.BRIGHT}CONSOLIDATION SUMMARY{Colors.RESET}")
    print(f"{Colors.CYAN}{'-' * 50}{Colors.RESET}")
    
    # Impact Statistics
    print(f"{Colors.WHITE}{Colors.BRIGHT}Impact Statistics:{Colors.RESET}")
    print(f"  • Original Vulnerabilities: {Colors.YELLOW}{original_count}{Colors.RESET}")
    print(f"  • Vulnerabilities Consolidated: {Colors.ORANGE}{reduction}{Colors.RESET}")
    print(f"  • Consolidated Into: {Colors.GREEN}{consolidated_count}{Colors.RESET} categories")
    print(f"  • Final Vulnerability Count: {Colors.GREEN}{final_count}{Colors.RESET}")
    print(f"  • Reduction: {Colors.MAGENTA}{Colors.BRIGHT}{reduction}{Colors.RESET} plugins")
    
    # Rules Applied
    print(f"\n{Colors.WHITE}{Colors.BRIGHT}Rules Applied:{Colors.RESET}")
    for rule_name in metadata['rules_applied']:
        print(f"  • {Colors.GREEN}{rule_name}{Colors.RESET}")
    
    # Consolidated Categories
    print(f"\n{Colors.WHITE}{Colors.BRIGHT}Consolidated Categories:{Colors.RESET}")
    for rule_name, rule_data in consolidated_vulns.items():
        title = rule_data['title']
        plugin_count = len(rule_data.get('consolidated_plugins', []))
        service_count = len(rule_data.get('affected_services', {}))
        
        # Color code by severity
        severity = rule_data.get('severity', 0)
        if severity >= 3:
            severity_color = Colors.RED + Colors.BRIGHT
        elif severity >= 2:
            severity_color = Colors.ORANGE + Colors.BRIGHT
        elif severity >= 1:
            severity_color = Colors.YELLOW + Colors.BRIGHT
        else:
            severity_color = Colors.GREEN
        
        print(f"  • {severity_color}{title}{Colors.RESET}")
        print(f"    └─ {Colors.CYAN}{plugin_count}{Colors.RESET} plugins → {Colors.CYAN}{service_count}{Colors.RESET} affected services")
    
    print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")

def display_api_summary(api_data: List[Dict[str, Any]]):
    """Display formatted API output summary matching YAPP aesthetic"""
    if not api_data:
        return
    
    # Calculate statistics
    total_findings = len(api_data)
    finding_ids = [finding['finding_id'] for finding in api_data]
    unique_finding_ids = list(set(finding_ids))
    
    # Count total affected entities and check for truncated findings
    total_entities = 0
    truncated_findings = 0
    for finding in api_data:
        affected_entities = finding.get('affected_entities', '')
        if affected_entities:
            if 'external document' in affected_entities and 'replaceMe' in affected_entities:
                truncated_findings += 1
            else:
                # Count <br /> occurrences + 1 for total entities
                entity_count = affected_entities.count('<br />') + 1
                total_entities += entity_count
    
    # Print API Summary
    print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.WHITE}{Colors.BRIGHT}API OUTPUT SUMMARY{Colors.RESET}")
    print(f"{Colors.CYAN}{'-' * 50}{Colors.RESET}")
    
    # Generation Statistics
    print(f"{Colors.WHITE}{Colors.BRIGHT}Generation Statistics:{Colors.RESET}")
    print(f"  • API Findings Generated: {Colors.GREEN}{total_findings}{Colors.RESET}")
    print(f"  • Unique Stock Finding IDs: {Colors.GREEN}{len(unique_finding_ids)}{Colors.RESET}")
    print(f"  • Total Affected Entities: {Colors.GREEN}{total_entities}{Colors.RESET}")
    
    if truncated_findings > 0:
        print(f"  • Findings with Entity Limit Applied: {Colors.ORANGE}{truncated_findings}{Colors.RESET}")
    
    # Stock Finding IDs Used
    if unique_finding_ids:
        print(f"\n{Colors.WHITE}{Colors.BRIGHT}Stock Finding IDs Used:{Colors.RESET}")
        for finding_id in sorted(unique_finding_ids):
            # Count how many times this finding_id appears
            count = finding_ids.count(finding_id)
            if count > 1:
                print(f"  • Finding ID {Colors.GREEN}{finding_id}{Colors.RESET} ({Colors.CYAN}{count}{Colors.RESET} consolidated rules)")
            else:
                print(f"  • Finding ID {Colors.GREEN}{finding_id}{Colors.RESET}")
    
    print(f"\n{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")

def setup_argparse() -> argparse.ArgumentParser:
    """Setup and return argument parser"""
    parser = argparse.ArgumentParser(
        description='YAPP - Swiss Army Knife for Pentester File Processing',
        prog='yapp'
    )
    
    parser.add_argument(
        '-i', '--input-file',
        required=True,
        help='Path to input file (Nessus .nessus, Nmap .xml)'
    )
    
    parser.add_argument(
        '-t', '--file-type',
        choices=['auto', 'nessus', 'nmap'],
        default='auto',
        help='Input file type (default: auto-detect)'
    )
    
    parser.add_argument(
        '-of', '--output-folder',
        default='./output',
        help='Output folder path (default: ./output)'
    )
    
    parser.add_argument(
        '-on', '--output-name',
        help='Output file name (default: timestamp_<original-name>_Parsed.json)'
    )
    
    # Nessus-specific options
    nessus_group = parser.add_argument_group('Nessus options')
    nessus_group.add_argument(
        '-c', '--consolidate',
        action='store_true',
        help='Generate consolidated findings file based on rules (Nessus only)'
    )
    
    nessus_group.add_argument(
        '-a', '--api-output',
        action='store_true',
        help='Generate API-ready JSON format (requires --consolidate, Nessus only)'
    )
    
    nessus_group.add_argument(
        '-r', '--rules-file',
        help='Custom consolidation rules file (Nessus only)'
    )
    
    nessus_group.add_argument(
        '-el', '--entity-limit',
        type=int,
        help='Maximum number of affected entities per API finding (Nessus only)'
    )
    
    # Nmap-specific options
    nmap_group = parser.add_argument_group('Nmap options')
    nmap_group.add_argument(
        '-s', '--port-status',
        choices=['all', 'open', 'closed', 'filtered'],
        default='all',
        help='Filter by port status (Nmap only, default: all)'
    )
    
    parser.add_argument(
        '--no-output',
        action='store_true',
        help='Skip writing files, only display results'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    return parser

def process_file(
    input_file: str,
    file_type: str = "auto",
    port_status: str = "all",
    consolidate: bool = False,
    api_format: bool = False,
    rules_file: str = None,
    entity_limit: int = None
) -> Dict[str, Any]:
    """
    Process input file through the appropriate parser pipeline.
    
    Args:
        input_file: Path to input file
        file_type: File type ('auto', 'nessus', 'nmap')
        port_status: Port status filter for Nmap (all, open, closed, filtered)
        consolidate: Whether to apply consolidation rules (Nessus only)
        api_format: Whether to format for API consumption (Nessus only)
        rules_file: Custom consolidation rules file (Nessus only)
        entity_limit: Maximum number of affected entities per API finding (Nessus only)
        
    Returns:
        dict: Contains parsed data and optional consolidated/API data
        
    Raises:
        Various exceptions from parsers, consolidator, or formatter
    """
    results = {}
    
    # Auto-detect file type if needed
    if file_type == "auto":
        file_type = detect_file_type(input_file)
        print(f"{Colors.CYAN}Auto-detected file type: {Colors.GREEN}{file_type.upper()}{Colors.RESET}")
    
    # Parse based on file type
    if file_type == "nessus":
        parser = NessusParser(input_file)
        parsed_data = parser.parse()
        results['parsed'] = parsed_data
        results['file_type'] = 'nessus'
        
        # Optional consolidation (Nessus only)
        if consolidate:
            consolidator = VulnerabilityConsolidator(rules_file)
            consolidated_data = consolidator.consolidate(parsed_data)
            results['consolidated'] = consolidated_data
            
            # Optional API formatting (Nessus only)
            if api_format and consolidated_data:
                formatter = APIFormatter(entity_limit=entity_limit)
                api_data = formatter.format_for_api(consolidated_data)
                results['api_ready'] = api_data
                
    elif file_type == "nmap":
        parser = NmapParser(input_file)
        parsed_data = parser.parse(port_status_filter=port_status)
        results['parsed'] = parsed_data
        results['file_type'] = 'nmap'
        
    else:
        raise ValueError(f"Unsupported file type: {file_type}")
    
    return results

def main():
    """Main CLI execution function"""
    print_banner(__version__)
    
    # Setup logging
    log = setup_logging()
    
    # Parse arguments
    args = setup_argparse().parse_args()
    
    # Validate arguments
    if args.api_output and not args.consolidate:
        log.error("--api-output requires --consolidate flag")
        return 1
    
    if args.entity_limit is not None and args.entity_limit < 1:
        log.error("--entity-limit must be a positive integer")
        return 1
    
    # Check for Nessus-only options with other file types
    if args.file_type in ['nmap'] or (args.file_type == 'auto' and Path(args.input_file).suffix.lower() == '.xml'):
        nessus_only_options = []
        if args.consolidate:
            nessus_only_options.append("--consolidate")
        if args.api_output:
            nessus_only_options.append("--api-output")
        if args.rules_file:
            nessus_only_options.append("--rules-file")
        if args.entity_limit:
            nessus_only_options.append("--entity-limit")
        
        if nessus_only_options and args.file_type == 'nmap':
            log.warning(f"Ignoring Nessus-only options for Nmap file: {', '.join(nessus_only_options)}")
    
    try:
        # Process using the appropriate parser
        results = process_file(
            input_file=args.input_file,
            file_type=args.file_type,
            port_status=args.port_status,
            consolidate=args.consolidate,
            api_format=args.api_output,
            rules_file=args.rules_file,
            entity_limit=args.entity_limit
        )
        
        # Display results
        if 'parsed' in results and results['parsed']:
            display_summary(results['parsed'], results['file_type'])
        
        if 'consolidated' in results and results['consolidated']:
            display_consolidation_summary(results['consolidated'])
        
        if 'api_ready' in results and results['api_ready']:
            display_api_summary(results['api_ready'])
        
        # Write output files unless disabled
        if not args.no_output:
            output_folder = ensure_output_directory(args.output_folder)
            
            write_status = write_results_to_files(
                results, 
                args.input_file, 
                output_folder,
                custom_output_name=args.output_name
            )
            
            # Check if any writes failed
            failed_writes = [file_type for file_type, success in write_status.items() if not success]
            if failed_writes:
                log.warning(f"Failed to write files: {', '.join(failed_writes)}")
                return 1
        
        return 0
        
    except FileNotFoundError as e:
        log.error(f"File not found: {e}")
        return 1
    except ConsolidationError as e:
        log.error(f"Consolidation failed: {e}")
        return 1
    except FormatterError as e:
        log.error(f"API formatting failed: {e}")
        return 1
    except Exception as e:
        log.error(f"Unexpected error: {str(e)}")
        return 1

def cli_entry_point():
    """Entry point for console script."""
    sys.exit(main())

if __name__ == "__main__":
    cli_entry_point()