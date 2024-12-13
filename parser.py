import argparse
import xml.etree.ElementTree as ET
import json
from pathlib import Path
import sys
from collections import defaultdict
from typing import Dict, List, Any, Optional, Set

class NessusParser:
    """Parser for Nessus XML reports."""
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.tree = None
        self.root = None
        self.unique_vulns = defaultdict(set)
        self.discovered_ports = set()
        
    def parse(self) -> Dict[str, Any]:
        """Parse the Nessus XML file and return structured data."""
        try:
            self.tree = ET.parse(self.file_path)
            self.root = self.tree.getroot()
            
            raw_data = {
                'scan_info': self._get_scan_info(),
                'hosts': self._parse_hosts(),
                'statistics': self._generate_statistics()
            }
            
            # Create structured report
            structured_report = {
                'scan_info': self._format_scan_info(raw_data['scan_info']),
                'host_summary': self._format_host_summary(raw_data['hosts']),
                'vulnerabilities': self._format_vulnerabilities(raw_data['hosts'])
            }
            
            return structured_report
            
        except ET.ParseError as e:
            print(f"Error parsing XML file: {e}")
            sys.exit(1)
    
    def _get_scan_info(self) -> Dict[str, str]:
        """Extract scan policy information."""
        policy = self.root.find('.//Policy')
        return {
            'policy_name': policy.findtext('.//policyName') if policy is not None else 'Unknown',
            'scan_date': ''  # We can add this if available in the XML
        }
    
    def _parse_hosts(self) -> List[Dict[str, Any]]:
        """Parse all hosts and their findings."""
        hosts = []
        
        for report_host in self.root.findall('.//ReportHost'):
            host_data = {
                'properties': self._parse_host_properties(report_host),
                'vulnerabilities': self._parse_vulnerabilities(report_host)
            }
            hosts.append(host_data)
            
        return hosts
    
    def _parse_host_properties(self, host: ET.Element) -> Dict[str, str]:
        """Parse host properties."""
        properties = {}
        host_properties = host.find('HostProperties')
        
        if host_properties is not None:
            for tag in host_properties.findall('tag'):
                name = tag.get('name')
                value = tag.text
                if name and value:
                    properties[name] = value
                    
        return properties
    
    def _parse_vulnerabilities(self, host: ET.Element) -> List[Dict[str, Any]]:
        """Parse vulnerabilities for a host."""
        vulnerabilities = []
        
        for item in host.findall('ReportItem'):
            vuln = {
                'plugin_id': item.get('pluginID'),
                'plugin_name': item.get('pluginName'),
                'port': item.get('port'),
                'protocol': item.get('protocol'),
                'severity': item.get('severity'),
                'description': item.findtext('description', ''),
                'solution': item.findtext('solution', ''),
                'cvss_base_score': item.findtext('cvss_base_score', ''),
                'cvss3_base_score': item.findtext('cvss3_base_score', ''),
                'risk_factor': item.findtext('risk_factor', ''),
                'plugin_output': item.findtext('plugin_output', ''),
                'cve': [cve.text for cve in item.findall('cve')],
                'see_also': item.findtext('see_also', '').split('\n') if item.findtext('see_also') else []
            }
            vulnerabilities.append(vuln)
            
        return vulnerabilities

    def _format_vulnerabilities(self, hosts: List[Dict]) -> Dict:
        """Format vulnerabilities section"""
        vulnerabilities = {}
        
        for host in hosts:
            host_ip = host['properties'].get('host-ip', '')
            host_fqdn = host['properties'].get('host-fqdn', '')
            
            for vuln in host['vulnerabilities']:
                plugin_name = vuln['plugin_name']
                
                if plugin_name not in vulnerabilities:
                    vulnerabilities[plugin_name] = {
                        "plugin_id": vuln['plugin_id'],
                        "severity": vuln['severity'],
                        "risk_factor": vuln['risk_factor'],
                        "cvss3_base_score": vuln['cvss3_base_score'],
                        "description": vuln['description'],
                        "solution": vuln['solution'],
                        "plugin_output": vuln['plugin_output'],
                        "cve": vuln['cve'],
                        "references": vuln['see_also'],
                        "affected_ips": [],
                        "affected_fqdns": [],
                        "ports": []
                    }
                
                if host_ip:
                    if host_ip not in vulnerabilities[plugin_name]["affected_ips"]:
                        vulnerabilities[plugin_name]["affected_ips"].append(host_ip)
                    if host_fqdn and host_fqdn not in vulnerabilities[plugin_name]["affected_fqdns"]:
                        vulnerabilities[plugin_name]["affected_fqdns"].append(f"{host_ip} - {host_fqdn}")
                
                if vuln.get('port') and vuln.get('protocol'):
                    port_entry = f"{host_ip} - {vuln['protocol']}/{vuln['port']}"
                    if port_entry not in vulnerabilities[plugin_name]["ports"]:
                        vulnerabilities[plugin_name]["ports"].append(port_entry)
        
        return vulnerabilities

    def _format_host_summary(self, hosts: List[Dict]) -> Dict:
        """Format host summary section"""
        host_list = []
        vulns_per_host = defaultdict(lambda: defaultdict(int))
        port_map = defaultdict(set)
        
        for host in hosts:
            host_ip = host['properties'].get('host-ip', '')
            host_fqdn = host['properties'].get('host-fqdn', '')
            
            if host_ip:
                host_list.append({
                    "ip": host_ip,
                    "fqdn": host_fqdn
                })
            
            for vuln in host['vulnerabilities']:
                vulns_per_host[host_ip][vuln['risk_factor']] += 1
                
                if vuln.get('port') and vuln.get('protocol'):
                    formatted_port = f"{vuln['protocol']}/{vuln['port']}"
                    self.discovered_ports.add(formatted_port)
                    port_map[host_ip].add(formatted_port)
        
        return {
            "number_of_hosts": len(host_list),
            "number_of_unique_vulns_per_host_per_severity": dict(vulns_per_host),
            "list_of_hosts": host_list,
            "discovered_ports": sorted(list(self.discovered_ports)),
            "mapped_ports": {ip: sorted(list(ports)) for ip, ports in port_map.items()}
        }
    
    def _generate_statistics(self) -> Dict[str, Any]:
        """Generate statistics about the scan."""
        severity_counts = {'0': 0, '1': 0, '2': 0, '3': 0, '4': 0}
        host_count = len(self.root.findall('.//ReportHost'))
        
        for item in self.root.findall('.//ReportItem'):
            severity = item.get('severity', '0')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            'total_hosts': host_count,
            'severity_counts': {
                'critical': severity_counts['4'],
                'high': severity_counts['3'],
                'medium': severity_counts['2'],
                'low': severity_counts['1'],
                'info': severity_counts['0']
            }
        }

    def _format_scan_info(self, scan_info: Dict) -> Dict:
        """Format scan information section"""
        return {
            "policy_name": scan_info['policy_name'],
            "scan_date": scan_info['scan_date']
        }

def main():
    parser = argparse.ArgumentParser(description='Nessus XML to JSON parser')
    parser.add_argument('-f', '--file', required=True, help='Path to Nessus XML file')
    parser.add_argument('-o', '--output', help='Output JSON file path')
    args = parser.parse_args()
    
    nessus_parser = NessusParser(args.file)
    parsed_data = nessus_parser.parse()
    
    # Output handling
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(parsed_data, f, indent=2)
        print(f"Results written to {args.output}")
    else:
        print(json.dumps(parsed_data, indent=2))
    
    # Print summary (based on host_summary data)
    host_summary = parsed_data['host_summary']
    print("\nScan Summary:")
    print(f"Total Hosts: {host_summary['number_of_hosts']}")
    print(f"\nDiscovered Ports: {len(host_summary['discovered_ports'])}")
    
    # Print vulnerabilities per severity across all hosts
    total_per_severity = defaultdict(int)
    for host_vulns in host_summary['number_of_unique_vulns_per_host_per_severity'].values():
        for severity, count in host_vulns.items():
            total_per_severity[severity] += count
    
    print("\nFindings by Severity:")
    severity_names = {'4': 'Critical', '3': 'High', '2': 'Medium', '1': 'Low', '0': 'Info'}
    for severity, name in severity_names.items():
        if str(severity) in total_per_severity:
            print(f"{name}: {total_per_severity[str(severity)]}")

if __name__ == "__main__":
    main()