import argparse

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
    
    return parser