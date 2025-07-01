import argparse
from typing import Dict, Any, List

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

def print_banner(v: str):
    """Print YANP ASCII art banner"""
    banner = """
▓██   ██▓ ▄▄▄       ███▄    █  ██▓███  
 ▒██  ██▒▒████▄     ██ ▀█   █ ▓██░  ██▒
  ▒██ ██░▒██  ▀█▄  ▓██  ▀█ ██▒▓██░ ██▓▒
  ░ ▐██▓░░██▄▄▄▄██ ▓██▒  ▐▌██▒▒██▄█▓▒ ▒
  ░ ██▒▓░ ▓█   ▓██▒▒██░   ▓██░▒██▒ ░  ░
   ██▒▒▒  ▒▒   ▓▒█░░ ▒░   ▒ ▒ ▒▓▒░ ░  ░
 ▓██ ░▒░   ▒   ▒▒ ░░ ░░   ░ ▒░░▒ ░     
 ▒ ▒ ░░    ░   ▒      ░   ░ ░ ░░       
 ░ ░           ░  ░         ░          
 ░ ░                                   """

    tagline = "Same shit, different parser"
    author = "By @FlyingPhishy"
    version = f"             v{v}"

    print(f"{Colors.GREEN}{Colors.BRIGHT}{banner}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BRIGHT}{version}{Colors.RESET}\n")
    print(f"{Colors.YELLOW}{Colors.BRIGHT}{tagline}{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BRIGHT}{author}{Colors.RESET}\n")

def display_summary(parsed_data: dict):
    """Display formatted summary of scan results"""
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
    print(f"{Colors.WHITE}{Colors.BRIGHT}SCAN SUMMARY{Colors.RESET}")
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
        # Safely get count with default of 0
        count = stats['vulnerabilities']['by_severity'].get(risk, 0)
        bullet = "•"
        print(f"  {bullet} {risk_colors[risk]}{risk}: {count}{Colors.RESET}")

    # Service Information (only if services exist)
    if stats['ports']['services']:
        print(f"\n{Colors.WHITE}{Colors.BRIGHT}Service Information:{Colors.RESET}")
        for service, count in stats['ports']['services'].items():
            print(f"  • {service}: {Colors.GREEN}{count}{Colors.RESET}")
    
    print(f"{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")

def display_consolidation_summary(consolidated_data: dict):
    """Display formatted consolidation summary matching YANP aesthetic"""
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
    """Display formatted API output summary matching YANP aesthetic"""
    if not api_data:
        return
    
    # Calculate statistics
    total_findings = len(api_data)
    finding_ids = [finding['finding_id'] for finding in api_data]
    unique_finding_ids = list(set(finding_ids))
    
    # Count total affected entities across all findings
    total_entities = 0
    for finding in api_data:
        affected_entities = finding.get('affected_entities', '')
        if affected_entities:
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
        description='Nessus XML Parser - Converts Nessus XML to JSON format'
    )
    
    parser.add_argument(
        '-n', '--nessus-file',
        required=True,
        help='Path to input Nessus XML file'
    )
    
    parser.add_argument(
        '-of', '--output-folder',
        default='./output',
        help='Output folder path (default: ./output)'
    )
    
    parser.add_argument(
        '-on', '--output-name',
        help='Output file name (default: timestamp_<original-name>_Parsed_Nessus.json)'
    )
    
    parser.add_argument(
        '-c', '--consolidate',
        action='store_true',
        help='Generate consolidated findings file based on rules'
    )
    
    parser.add_argument(
        '-a', '--api-output',
        action='store_true',
        help='Generate API-ready JSON format (requires --consolidate)'
    )
    return parser