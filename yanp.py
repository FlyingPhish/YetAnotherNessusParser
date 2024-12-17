from colorama import init, Fore, Style
from pathlib import Path
from modules import (
    logger,
    file_utils,
    cli,
    json_utils,
    nessus
)
init(autoreset=True) 

def print_banner():
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
    version = "             v1.9.2"

    print(f"{Fore.GREEN}{Style.BRIGHT}{banner}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}{version}{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{tagline}{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}{author}{Style.RESET_ALL}\n")

def display_summary(parsed_data: dict):
    """Display formatted summary of scan results"""
    stats = parsed_data['stats']
    context = parsed_data['context']

    # Color mappings for risk factors
    risk_colors = {
        'Critical': Fore.MAGENTA + Style.BRIGHT,
        'High': Fore.RED + Style.BRIGHT,
        'Medium': '\033[38;5;214m' + Style.BRIGHT,
        'Low': Fore.YELLOW + Style.BRIGHT,
        'None': Fore.GREEN
    }

    # Print summary without timestamps
    print(f"\n{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}")
    print(f"{Fore.WHITE}{Style.BRIGHT}SCAN SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'-' * 50}{Style.RESET_ALL}")
    
    # Scan Context
    print(f"{Fore.WHITE}{Style.BRIGHT}Scan Context:{Style.RESET_ALL}")
    print(f"  • Start Time: {Fore.GREEN}{context['scan_start']}{Style.RESET_ALL}")
    print(f"  • End Time: {Fore.GREEN}{context['scan_end']}{Style.RESET_ALL}")
    print(f"  • Duration: {Fore.GREEN}{context['scan_duration']}{Style.RESET_ALL}")
    print(f"  • Policy: {Fore.GREEN}{context['policy_name']}{Style.RESET_ALL}")
    
    # Asset Information
    print(f"\n{Fore.WHITE}{Style.BRIGHT}Asset Information:{Style.RESET_ALL}")
    print(f"  • Total Hosts: {Fore.GREEN}{stats['hosts']['total']}{Style.RESET_ALL}")
    print(f"  • Unique IPs: {Fore.GREEN}{stats['hosts']['total_ips']}{Style.RESET_ALL}")
    print(f"  • Unique FQDNs: {Fore.GREEN}{stats['hosts']['total_fqdns']}{Style.RESET_ALL}")
    print(f"  • Discovered Ports: {Fore.GREEN}{stats['ports']['total_discovered']}{Style.RESET_ALL}")
    print(f"  • Credentialed Hosts: {Fore.GREEN}{stats['hosts']['credentialed_checks']}{Style.RESET_ALL}")
    
    # Vulnerability Summary
    print(f"\n{Fore.WHITE}{Style.BRIGHT}Vulnerability Summary:{Style.RESET_ALL}")
    risk_order = ['Critical', 'High', 'Medium', 'Low', 'None']
    
    for risk in risk_order:
        # Safely get count with default of 0
        count = stats['vulnerabilities']['by_severity'].get(risk, 0)
        bullet = "•"
        print(f"  {bullet} {risk_colors[risk]}{risk}: {count}{Style.RESET_ALL}")

    # Service Information (only if services exist)
    if stats['ports']['services']:
        print(f"\n{Fore.WHITE}{Style.BRIGHT}Service Information:{Style.RESET_ALL}")
        for service, count in stats['ports']['services'].items():
            print(f"  • {service}: {Fore.GREEN}{count}{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}{'=' * 50}{Style.RESET_ALL}\n")

def main():
    """Main execution function"""
    print_banner()
    # Setup logging
    log = logger.setup_logging()
    
    # Parse arguments
    args = cli.setup_argparse().parse_args()
    
    # Validate and create output directory
    output_folder = Path(args.output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)
    
    # Validate input file
    if not file_utils.validate_nessus_file(args.nessus_file):
        return 1

    # Initialize parser and parse file
    parser = nessus.NessusParser(args.nessus_file)
    parsed_data = parser.parse()
    
    if not parsed_data:
        log.error("Failed to parse Nessus file")
        return 1
    
    # Display formatted summary
    display_summary(parsed_data)

    # Set output filename and write results
    output_name = args.output_name or file_utils.get_default_output_name(args.nessus_file)
    output_path = output_folder / output_name
    
    # Write to JSON file
    if not json_utils.write_json_output(parsed_data, output_path):
        return 1

    return 0

if __name__ == "__main__":
    exit(main())