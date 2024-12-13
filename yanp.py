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
    version = "             v1.0.0"

    print(f"{Fore.GREEN}{Style.BRIGHT}{banner}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{Style.BRIGHT}{version}{Style.RESET_ALL}\n")
    print(f"{Fore.YELLOW}{Style.BRIGHT}{tagline}{Style.RESET_ALL}")
    print(f"{Fore.RED}{Style.BRIGHT}{author}{Style.RESET_ALL}\n")

def display_summary(parsed_data: dict):
    """Display formatted summary of scan results"""
    host_summary = parsed_data['host_summary']

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
    
    # Asset Information
    print(f"{Fore.WHITE}{Style.BRIGHT}Asset Information:{Style.RESET_ALL}")
    print(f"  • Unique IPs: {Fore.GREEN}{host_summary['number_of_unique_ips']}{Style.RESET_ALL}")
    print(f"  • Unique FQDNs: {Fore.GREEN}{host_summary['number_of_unique_fqdns']}{Style.RESET_ALL}")
    print(f"  • Discovered Ports: {Fore.GREEN}{len(host_summary['discovered_ports'])}{Style.RESET_ALL}")
    
    # Vulnerability Summary
    print(f"\n{Fore.WHITE}{Style.BRIGHT}Vulnerability Summary:{Style.RESET_ALL}")
    risk_order = ['Critical', 'High', 'Medium', 'Low', 'None']
    
    for risk in risk_order:
        count = host_summary['total_unique_vulns'][risk]
        bullet = "•"
        print(f"  {bullet} {risk_colors[risk]}{risk}: {count}{Style.RESET_ALL}")
    
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