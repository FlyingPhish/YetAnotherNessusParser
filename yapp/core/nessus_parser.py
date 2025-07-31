import logging
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Union

logger = logging.getLogger(__name__)

class NessusParser:
    """Parser for Nessus XML reports with restructured output format."""
    
    def __init__(self, file_path: str):
        """Initialize parser with file path."""
        self.file_path = Path(file_path)
        self.tree = None
        self.root = None
        self._reset_counters()
        
    def parse(self) -> Optional[Dict[str, Any]]:
        """
        Parse Nessus XML file and return structured data.
        
        Returns:
            dict: Parsed Nessus data with context, stats, hosts, and vulnerabilities
            
        Raises:
            FileNotFoundError: If the Nessus file doesn't exist
            ET.ParseError: If the XML is malformed
            ValueError: If the file is not a valid Nessus file
        """
        # Validate input file
        self._validate_file()
        
        try:
            self.tree = ET.parse(self.file_path)
            self.root = self.tree.getroot()
            
            # Parse main sections
            context = self._parse_context()
            hosts_data = self._parse_hosts()
            vulnerabilities = self._parse_vulnerabilities()
            
            # Generate statistics after parsing all data
            stats = self._generate_statistics(hosts_data, vulnerabilities)
            
            return {
                "context": context,
                "stats": stats,
                "hosts": hosts_data,
                "vulnerabilities": vulnerabilities
            }
            
        except ET.ParseError as e:
            logger.error(f"Error parsing XML file: {str(e)}")
            raise ET.ParseError(f"Invalid XML format in file: {self.file_path}")
        except Exception as e:
            logger.error(f"Unexpected error during parsing: {str(e)}")
            raise
    
    def _validate_file(self) -> None:
        """Validate if the input file is accessible and has correct format."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"File not found: {self.file_path}")
        
        if self.file_path.suffix.lower() != '.nessus':
            raise ValueError(f"Invalid file extension: {self.file_path.suffix}. Expected .nessus")
        
        # Basic XML validation
        try:
            ET.parse(self.file_path)
        except ET.ParseError as e:
            raise ET.ParseError(f"Invalid XML format in file: {self.file_path}")
    
    def _reset_counters(self):
        """Reset internal counters for fresh parsing."""
        self._host_counter = 0
        
        # Service tracking - separate unique instances from findings
        self._unique_service_instances = set()  # Track unique (host_id, port, service) combinations
        self._service_findings_counts = defaultdict(int)  # Track findings per service type (crit-low only)
        
        # Vulnerability tracking
        self._severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "None": 0
        }
        self._family_counts = defaultdict(int)
        self._total_vulnerabilities = 0
    
    def _parse_context(self) -> Dict[str, Any]:
        """Parse scan context information."""
        policy = self.root.find('.//Policy')
        report = self.root.find('.//Report')
        
        # Get scan timestamps from policy preferences
        scan_start = None
        scan_end = None
        
        prefs = self.root.findall('.//preference')
        for pref in prefs:
            name = pref.findtext('name')
            if name == 'scan_start_timestamp':
                scan_start = pref.findtext('value')
            elif name == 'scan_end_timestamp':
                scan_end = pref.findtext('value')
        
        return {
            "scan_id": report.get('name') if report is not None else "",
            "scan_name": report.get('name') if report is not None else "",
            "policy_name": policy.findtext('.//policyName') if policy is not None else "",
            "scan_start": self._format_datetime(scan_start) if scan_start else "",
            "scan_end": self._format_datetime(scan_end) if scan_end else "",
            "scan_duration": self._calculate_duration(scan_start, scan_end) if scan_start and scan_end else "",
        }
    
    def _parse_hosts(self) -> Dict[str, Dict[str, Any]]:
        """Parse host information with sequential IDs."""
        hosts = {}
        
        for host_elem in self.root.findall('.//ReportHost'):
            host_id = str(self._get_host_id())
            properties = host_elem.find('HostProperties')
            
            if properties is None:
                continue
                
            # Extract host basic information
            ip = self._get_tag_value(properties, 'host-ip')
            
            # Handle multiple FQDNs
            fqdns_str = self._get_tag_value(properties, 'host-fqdns')
            fqdns = self._parse_html_encoded_fqdns(fqdns_str) if fqdns_str else []
            
            # Fallback to single FQDN if host-fqdns not present
            if not fqdns:
                single_fqdn = self._get_tag_value(properties, 'host-fqdn')
                if single_fqdn:
                    fqdns = [single_fqdn]
            
            os = self._get_tag_value(properties, 'operating-system')
            start_time = self._get_tag_value(properties, 'HOST_START')
            end_time = self._get_tag_value(properties, 'HOST_END')
            credentialed_scan = self._get_tag_value(properties, 'Credentialed_Scan')

            # Initialize vulnerability counts
            vuln_counts = {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "None": 0
            }
            
            # Initialize ports structure
            ports = {}
            
            # Track unique plugin IDs per severity
            severity_plugin_ids = {
                "Critical": set(),
                "High": set(),
                "Medium": set(),
                "Low": set(),
                "None": set()
            }
            
            # Process each vulnerability for this host
            for item in host_elem.findall('ReportItem'):
                plugin_id = item.get('pluginID')
                severity = self._get_severity_label(item.get('severity', '0'))
                severity_plugin_ids[severity].add(plugin_id)
                
                # Process port and service information for statistics
                port = item.get('port', '')
                protocol = item.get('protocol', '')
                service = item.get('svc_name', '')
                
                if port and protocol:
                    port_key = f"{port}/{protocol}"
                    if port_key not in ports:
                        ports[port_key] = {
                            "service": service,
                            "vulnerabilities": []
                        }
                    if plugin_id not in ports[port_key]["vulnerabilities"]:
                        ports[port_key]["vulnerabilities"].append(plugin_id)
                    
                    # Track unique service instances
                    if service:
                        service_instance = f"{host_id}_{port}_{protocol}_{service}"
                        self._unique_service_instances.add(service_instance)
                        
                        # Track findings per service type (Critical-Low only, exclude None/Info)
                        if severity in ['Critical', 'High', 'Medium', 'Low']:
                            self._service_findings_counts[service] += 1
            
            # Convert sets to counts
            vuln_counts = {
                severity: len(plugins)
                for severity, plugins in severity_plugin_ids.items()
            }
            
            # Build host entry
            hosts[host_id] = {
                "ip": ip,
                "fqdns": fqdns,
                "os": os,
                "scan_start": self._format_datetime(start_time) if start_time else "",
                "scan_end": self._format_datetime(end_time) if end_time else "",
                "credentialed_scan": credentialed_scan.lower() == 'true' if credentialed_scan else False,
                "vulnerabilities": vuln_counts,
                "ports": ports
            }
            
        return hosts
    
    def _parse_vulnerabilities(self) -> Dict[str, Dict[str, Any]]:
        """Parse vulnerability information with enhanced structure."""
        vulnerabilities = {}
        processed_plugins = set()
        
        for host_elem in self.root.findall('.//ReportHost'):
            host_properties = host_elem.find('HostProperties')
            if host_properties is None:
                continue
                
            host_id = str(self._get_host_id())  # Get sequential host ID
            host_ip = self._get_tag_value(host_properties, 'host-ip')
            host_fqdn = self._get_tag_value(host_properties, 'host-fqdn')
            
            for item in host_elem.findall('ReportItem'):
                plugin_id = item.get('pluginID')
                
                # Process new vulnerabilities - count each plugin_id only once globally
                if plugin_id not in vulnerabilities:
                    vulnerabilities[plugin_id] = {
                        "name": item.get('pluginName', ''),
                        "family": item.get('pluginFamily', ''),
                        "severity": int(item.get('severity', 0)),
                        "risk_factor": item.findtext('risk_factor', ''),
                        "cvss": {
                            "base_score": float(item.findtext('cvss_base_score', 0)),
                            "temporal_score": float(item.findtext('cvss_temporal_score', 0)),
                            "vector": item.findtext('cvss_vector', '')
                        },
                        "cvss3": {
                            "base_score": float(item.findtext('cvss3_base_score', 0)),
                            "temporal_score": float(item.findtext('cvss3_temporal_score', 0)),
                            "vector": item.findtext('cvss3_vector', '')
                        },
                        "description": item.findtext('description', ''),
                        "synopsis": item.findtext('synopsis', ''),
                        "solution": item.findtext('solution', ''),
                        "see_also": [ref.strip() for ref in item.findtext('see_also', '').split('\n') if ref.strip()],
                        "cve": [cve.text for cve in item.findall('cve')],
                        "cwe": [cwe.text for cwe in item.findall('cwe')],
                        "xref": [xref.text for xref in item.findall('xref')],
                        "affected_hosts": {}
                    }
                    
                    # Update global statistics - count each unique plugin_id once
                    self._family_counts[item.get('pluginFamily', '')] += 1
                    self._total_vulnerabilities += 1
                    severity = self._get_severity_label(item.get('severity', '0'))
                    self._severity_counts[severity] += 1
                
                # Add host-specific information using sequential host ID
                host_plugin_key = f"{plugin_id}_{host_id}"  # Unique key for tracking
                if host_plugin_key not in processed_plugins:
                    port = item.get('port', '')
                    protocol = item.get('protocol', '')
                    port_info = f"{port}/{protocol}" if port and protocol else ""
                    
                    vulnerabilities[plugin_id]["affected_hosts"][host_id] = {
                        "ip": host_ip,
                        "fqdn": host_fqdn,
                        "ports": [port_info] if port_info else [],
                        "plugin_output": item.findtext('plugin_output', '')
                    }
                    
                    processed_plugins.add(host_plugin_key)
        
        return vulnerabilities
    
    def _generate_statistics(self, hosts: Dict[str, Dict], vulnerabilities: Dict[str, Dict]) -> Dict[str, Any]:
        """Generate comprehensive statistics."""
        # Count unique hosts, IPs and FQDNs
        total_hosts = len(hosts)
        unique_ips = set()
        unique_fqdns = set()
        credentialed_hosts = 0
        discovered_ports = set()
        multi_fqdn_hosts = 0  # Counter for hosts with multiple FQDNs
        
        # Process host data and count credentialed hosts efficiently
        for host_data in hosts.values():
            ip = host_data.get('ip', '')
            if ip:
                unique_ips.add(ip)
            
            # Count credentialed hosts from parsed data
            if host_data.get('credentialed_scan', False):
                credentialed_hosts += 1
            
            # Process FQDNs and count hosts with multiple valid FQDNs
            fqdns = host_data.get('fqdns', [])
            if fqdns:
                # Filter out IP-based FQDNs
                valid_fqdns = [fqdn for fqdn in fqdns if ip not in fqdn]
                unique_fqdns.update(valid_fqdns)
                
                # If we have more than one valid FQDN, increment counter
                if len(valid_fqdns) > 1:
                    multi_fqdn_hosts += 1
                
            # Collect discovered ports
            for port in host_data.get('ports', {}).keys():
                discovered_ports.add(port)
        
        # Generate service statistics
        unique_services = {}
        for service_instance in self._unique_service_instances:
            # Extract service name from instance (format: host_id_port_protocol_service)
            parts = service_instance.split('_')
            if len(parts) >= 4:
                service_name = '_'.join(parts[3:])  # Handle service names with underscores
                unique_services[service_name] = unique_services.get(service_name, 0) + 1
        
        return {
            "hosts": {
                "total": total_hosts,
                "total_ips": len(unique_ips),
                "total_fqdns": len(unique_fqdns),
                "multi_fqdn_hosts": multi_fqdn_hosts,
                "credentialed_checks": credentialed_hosts
            },
            "ports": {
                "total_discovered": len(discovered_ports),
                "list": sorted(list(discovered_ports))
            },
            "services": {
                "unique_counts": dict(unique_services),
                "findings_counts": dict(self._service_findings_counts)
            },
            "vulnerabilities": {
                "total": self._total_vulnerabilities,
                "by_severity": dict(self._severity_counts),
                "by_family": dict(self._family_counts)
            }
        }
    
    def _parse_html_encoded_fqdns(self, fqdns_str: str) -> list[str]:
        """
        Parse HTML-encoded JSON string containing FQDN data.
        
        Args:
            fqdns_str: HTML-encoded JSON string with FQDN data
            
        Returns:
            List of FQDN strings
        """
        import json
        
        try:
            # Remove HTML encoding and parse JSON
            cleaned_str = fqdns_str.replace('&quot;', '"')
            fqdns_data = json.loads(cleaned_str)
            
            # Extract all unique FQDNs
            return [entry['FQDN'] for entry in fqdns_data if 'FQDN' in entry]
        except (json.JSONDecodeError, TypeError):
            logger.debug(f"Failed to parse FQDN JSON: {fqdns_str}")
            return []
    
    # Helper methods
    def _get_host_id(self) -> int:
        """Generate sequential host ID."""
        self._host_counter += 1
        return self._host_counter
    
    def _get_tag_value(self, properties: ET.Element, tag_name: str) -> str:
        """Get value of a specific tag from host properties."""
        tag = properties.find(f".//tag[@name='{tag_name}']")
        return tag.text if tag is not None else ""
    
    def _format_datetime(self, timestamp: Union[str, int]) -> str:
        """Format datetime to d-m-y h:m:s format.
        Args:
            timestamp: Either Unix timestamp (int/str) or formatted date string
        """
        try:
            # Handle Unix timestamp
            if str(timestamp).isdigit():
                dt = datetime.fromtimestamp(int(timestamp))
                return dt.strftime("%d-%m-%Y %H:%M:%S")
            
            # Handle formatted date string
            dt = datetime.strptime(timestamp, "%a %b %d %H:%M:%S %Y")
            return dt.strftime("%d-%m-%Y %H:%M:%S")
        except (ValueError, TypeError):
            return ""
    
    def _calculate_duration(self, start: Union[str, int], end: Union[str, int]) -> str:
        """Calculate scan duration from timestamps."""
        try:
            # Convert to datetime objects
            if str(start).isdigit() and str(end).isdigit():
                start_dt = datetime.fromtimestamp(int(start))
                end_dt = datetime.fromtimestamp(int(end))
            else:
                start_dt = datetime.strptime(start, "%a %b %d %H:%M:%S %Y")
                end_dt = datetime.strptime(end, "%a %b %d %H:%M:%S %Y")
            
            duration = end_dt - start_dt
            return str(duration)
        except (ValueError, TypeError):
            return ""
    
    def _get_severity_label(self, severity: str) -> str:
        """Convert severity number to label."""
        severity_map = {
            "4": "Critical",
            "3": "High",
            "2": "Medium",
            "1": "Low",
            "0": "None"
        }
        return severity_map.get(severity, "None")