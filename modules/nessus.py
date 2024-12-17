import logging
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from typing import Dict, Any, Optional, List, Set

logger = logging.getLogger(__name__)

class NessusParser:
    """Parser for Nessus XML reports with restructured output format."""
    
    def __init__(self, file_path: str):
        """Initialize parser with file path."""
        self.file_path = file_path
        self.tree = None
        self.root = None
        self._host_counter = 0
        self._service_counts = defaultdict(int)
        self._family_counts = defaultdict(int)
        self._total_vulnerabilities = 0
        self._severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "None": 0
        }
        
    def parse(self) -> Optional[Dict[str, Any]]:
        """Parse Nessus XML file and return structured data."""
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
            return None
        except Exception as e:
            logger.error(f"Unexpected error during parsing: {str(e)}")
            return None
    
    def _parse_context(self) -> Dict[str, Any]:
        """Parse scan context information."""
        policy = self.root.find('.//Policy')
        report = self.root.find('.//Report')
        
        # Find earliest start and latest end times across all hosts
        start_times = []
        end_times = []
        for host in self.root.findall('.//ReportHost'):
            props = host.find('HostProperties')
            if props is not None:
                start = self._get_tag_value(props, 'HOST_START')
                end = self._get_tag_value(props, 'HOST_END')
                if start:
                    start_times.append(start)
                if end:
                    end_times.append(end)
        
        scan_start = min(start_times) if start_times else None
        scan_end = max(end_times) if end_times else None
        
        return {
            "scan_id": report.get('name') if report is not None else "",
            "scan_name": report.get('name') if report is not None else "",
            "policy_name": policy.findtext('.//policyName') if policy is not None else "",
            "scan_start": self._format_datetime(scan_start) if scan_start else "",
            "scan_end": self._format_datetime(scan_end) if scan_end else "",
            "scan_duration": self._calculate_duration(scan_start, scan_end) if scan_start and scan_end else "",
            "scanner_version": self._get_scanner_version(),
            "plugin_feed": self._get_plugin_feed()
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
            fqdn = self._get_tag_value(properties, 'host-fqdn')
            os = self._get_tag_value(properties, 'operating-system')
            start_time = self._get_tag_value(properties, 'HOST_START')
            end_time = self._get_tag_value(properties, 'HOST_END')
            
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
                
                # Process port information
                port = item.get('port', '')
                protocol = item.get('protocol', '')
                if port and protocol:
                    port_key = f"{port}/{protocol}"
                    if port_key not in ports:
                        ports[port_key] = {
                            "service": item.get('svc_name', ''),
                            "vulnerabilities": []
                        }
                    if plugin_id not in ports[port_key]["vulnerabilities"]:
                        ports[port_key]["vulnerabilities"].append(plugin_id)
            
            # Convert sets to counts
            vuln_counts = {
                severity: len(plugins)
                for severity, plugins in severity_plugin_ids.items()
            }
            
            # Build host entry
            hosts[host_id] = {
                "ip": ip,
                "fqdn": fqdn,
                "os": os,
                "scan_start": self._format_datetime(start_time) if start_time else "",
                "scan_end": self._format_datetime(end_time) if end_time else "",
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
                
                # Process new vulnerabilities
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
                    
                    # Update statistics
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
                    
                    # Update service statistics
                    service = item.get('svc_name', '')
                    if service:
                        self._service_counts[service] += 1
        
        return vulnerabilities
    
    def _generate_statistics(self, hosts: Dict[str, Dict], vulnerabilities: Dict[str, Dict]) -> Dict[str, Any]:
        """Generate comprehensive statistics."""
        # Count unique hosts, IPs and FQDNs
        total_hosts = len(hosts)
        unique_ips = set()
        unique_fqdns = set()
        credentialed_hosts = 0
        discovered_ports = set()
        
        for host_data in hosts.values():
            if host_data.get('ip'):
                unique_ips.add(host_data['ip'])
            if host_data.get('fqdn'):
                unique_fqdns.add(host_data['fqdn'])
            
            # Count credentialed checks (this might need adjustment based on your criteria)
            if host_data.get('os'):  # Assuming OS detection indicates credential usage
                credentialed_hosts += 0
                
            # Collect discovered ports
            for port in host_data.get('ports', {}).keys():
                discovered_ports.add(port)
        
        return {
            "hosts": {
                "total": total_hosts,
                "total_ips": len(unique_ips),
                "total_fqdns": len(unique_fqdns),
                "credentialed_checks": credentialed_hosts
            },
            "ports": {
                "total_discovered": len(discovered_ports),
                "list": sorted(list(discovered_ports)),
                "services": dict(self._service_counts)
            },
            "vulnerabilities": {
                "total": self._total_vulnerabilities,
                "by_severity": dict(self._severity_counts),
                "by_family": dict(self._family_counts)
            }
        }
    
    # Helper methods
    def _get_host_id(self) -> int:
        """Generate sequential host ID."""
        self._host_counter += 1
        return self._host_counter
    
    def _get_tag_value(self, properties: ET.Element, tag_name: str) -> str:
        """Get value of a specific tag from host properties."""
        tag = properties.find(f".//tag[@name='{tag_name}']")
        return tag.text if tag is not None else ""
    
    def _format_datetime(self, timestamp: str) -> str:
        """Format datetime to d-m-y h:m:s format."""
        try:
            dt = datetime.strptime(timestamp, "%a %b %d %H:%M:%S %Y")
            return dt.strftime("%d-%m-%Y %H:%M:%S")
        except (ValueError, TypeError):
            return ""
    
    def _calculate_duration(self, start: str, end: str) -> str:
        """Calculate scan duration."""
        try:
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
    
    def _get_scanner_version(self) -> str:
        """Get scanner version from preferences."""
        prefs = self.root.find('.//ServerPreferences')
        if prefs is not None:
            for pref in prefs.findall('.//preference'):
                if pref.findtext('name') == 'scanner_version':
                    return pref.findtext('value', '')
        return ""
    
    def _get_plugin_feed(self) -> str:
        """Get plugin feed version from preferences."""
        prefs = self.root.find('.//ServerPreferences')
        if prefs is not None:
            for pref in prefs.findall('.//preference'):
                if pref.findtext('name') == 'plugin_feed':
                    return pref.findtext('value', '')
        return ""