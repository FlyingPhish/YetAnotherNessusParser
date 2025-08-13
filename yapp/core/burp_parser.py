import logging
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Set
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)

class BurpParser:
    """Parser for Burp Suite XML export files with structured output format."""
    
    def __init__(self, file_path: str):
        """Initialize parser with file path."""
        self.file_path = Path(file_path)
        self.tree = None
        self.root = None
        self._reset_counters()
        
    def parse(self) -> Optional[Dict[str, Any]]:
        """
        Parse Burp XML file and return structured data.
        
        Returns:
            dict: Parsed Burp data with context, stats, hosts, and vulnerabilities
            
        Raises:
            FileNotFoundError: If the Burp file doesn't exist
            ET.ParseError: If the XML is malformed
            ValueError: If the file is not a valid Burp file
        """
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
        
        if self.file_path.suffix.lower() != '.xml':
            raise ValueError(f"Invalid file extension: {self.file_path.suffix}. Expected .xml")
        
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
            
            # Validate Burp XML structure
            if root.tag != 'issues':
                raise ValueError(f"Not a Burp XML file: root element is '{root.tag}', expected 'issues'")
            
            if 'burpVersion' not in root.attrib:
                raise ValueError("Not a Burp XML file: missing 'burpVersion' attribute")
                
        except ET.ParseError as e:
            raise ET.ParseError(f"Invalid XML format in file: {self.file_path}")
    
    def _reset_counters(self):
        """Reset internal counters for fresh parsing."""
        self._host_counter = 0
        self._unique_service_instances = set()
        self._service_findings_counts = defaultdict(int)
        self._severity_counts = {
            "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0
        }
        self._issue_type_counts = defaultdict(int)
        self._total_vulnerabilities = 0
        
        # Track hosts during single-pass parsing
        self._host_map = {}  # URL key -> host_id mapping
    
    def _parse_context(self) -> Dict[str, Any]:
        """Parse scan context information."""
        burp_version = self.root.get('burpVersion', '')
        export_time = self.root.get('exportTime', '')
        
        formatted_time = self._format_datetime(export_time) if export_time else ""
        scan_id = f"burp_export_{formatted_time.replace(' ', '_').replace(':', '').replace('-', '')}" if formatted_time else "burp_export_unknown"
        
        return {
            "scan_id": scan_id,
            "scan_name": f"Burp Suite Export ({burp_version})",
            "scan_start": formatted_time,
            "scan_end": formatted_time,
            "scan_duration": "0:00:00",
            "burp_version": burp_version,
            "export_time": formatted_time
        }
    
    def _parse_hosts(self) -> Dict[str, Dict[str, Any]]:
        """Parse host information with sequential IDs using single-pass approach."""
        hosts = {}
        
        # Single pass through issues to collect hosts and count vulnerabilities
        for issue_elem in self.root.findall('issue'):
            host_elem = issue_elem.find('host')
            if host_elem is None:
                continue
                
            host_url = (host_elem.text or "").strip()
            if not host_url:
                continue
                
            host_ip = host_elem.get('ip', '')
            parsed_url = urlparse(host_url)
            hostname = parsed_url.hostname or ""
            port = parsed_url.port or self._get_default_port(parsed_url.scheme)
            
            # Create consistent host key
            host_key = f"{hostname}:{port}" if hostname else host_url
            
            # Get or create host entry
            if host_key not in self._host_map:
                host_id = str(self._get_host_id())
                self._host_map[host_key] = host_id
                
                hosts[host_id] = {
                    "ip": host_ip,
                    "fqdns": [hostname] if hostname else [],
                    "url": host_url,
                    "scheme": parsed_url.scheme,
                    "port": port,
                    "vulnerabilities": {
                        "Critical": 0, "High": 0, "Medium": 0, "Low": 0, "None": 0
                    },
                    "paths": []
                }
            
            # Get host_id and update vulnerability counts
            host_id = self._host_map[host_key]
            severity_elem = issue_elem.find('severity')
            severity = self._get_severity_label(severity_elem.text if severity_elem is not None else "")
            hosts[host_id]["vulnerabilities"][severity] += 1
            
            # Track path
            path_elem = issue_elem.find('path')
            path = (path_elem.text or "/").strip()
            if path not in hosts[host_id]["paths"]:
                hosts[host_id]["paths"].append(path)
            
            # Track service for statistics
            service_name = f"{parsed_url.scheme}_web_service"
            service_instance = f"{host_id}_{port}_{service_name}"
            self._unique_service_instances.add(service_instance)
            
            if severity in ['Critical', 'High', 'Medium', 'Low']:
                self._service_findings_counts[service_name] += 1
        
        # Sort paths for consistent output
        for host_data in hosts.values():
            host_data["paths"].sort()
            
        return hosts
    
    def _parse_vulnerabilities(self) -> Dict[str, Dict[str, Any]]:
        """Parse vulnerability information with enhanced structure."""
        vulnerabilities = {}
        processed_vulns = set()
        
        for issue_elem in self.root.findall('issue'):
            # Extract core issue data
            serial_number = issue_elem.findtext('serialNumber', '')
            issue_type = issue_elem.findtext('type', '')
            name = issue_elem.findtext('name', '')
            severity_text = issue_elem.findtext('severity', '')
            confidence = issue_elem.findtext('confidence', '')
            
            # Use serial number as unique ID, fallback to type+name hash
            vuln_id = serial_number if serial_number else f"type_{issue_type}_{hash(name) % 10000}"
            
            # Process new vulnerabilities only once
            if vuln_id not in processed_vulns:
                vulnerabilities[vuln_id] = {
                    "name": name,
                    "type": issue_type,
                    "severity": self._get_severity_numeric(severity_text),
                    "confidence": confidence,
                    "issue_background": self._clean_html(issue_elem.findtext('issueBackground', '')),
                    "references": self._clean_html(issue_elem.findtext('references', '')),
                    "vulnerability_classifications": self._clean_html(issue_elem.findtext('vulnerabilityClassifications', '')),
                    "issue_detail": self._clean_html(issue_elem.findtext('issueDetail', '')),
                    "remediation_detail": self._clean_html(issue_elem.findtext('remediationDetail', '')),
                    "cwe": self._extract_cwe_references(issue_elem.findtext('vulnerabilityClassifications', '')),
                    "affected_hosts": {}
                }
                
                # Update global statistics
                self._issue_type_counts[name] += 1
                self._total_vulnerabilities += 1
                severity_label = self._get_severity_label(severity_text)
                self._severity_counts[severity_label] += 1
                
                processed_vulns.add(vuln_id)
            
            # Add host-specific information
            host_elem = issue_elem.find('host')
            if host_elem is not None:
                host_url = (host_elem.text or "").strip()
                if host_url:
                    host_ip = host_elem.get('ip', '')
                    parsed_url = urlparse(host_url)
                    hostname = parsed_url.hostname or ""
                    port = parsed_url.port or self._get_default_port(parsed_url.scheme)
                    host_key = f"{hostname}:{port}" if hostname else host_url
                    
                    if host_key in self._host_map:
                        host_id = self._host_map[host_key]
                        path = issue_elem.findtext('path', '/')
                        location = issue_elem.findtext('location', '')
                        
                        # Create unique affected host key
                        affected_key = f"{host_id}_{hash(path + location) % 1000}"
                        
                        vulnerabilities[vuln_id]["affected_hosts"][affected_key] = {
                            "ip": host_ip,
                            "fqdn": hostname,
                            "url": host_url,
                            "path": path,
                            "location": location,
                            "port": str(port)
                        }
        
        return vulnerabilities
    
    def _generate_statistics(self, hosts: Dict[str, Dict], vulnerabilities: Dict[str, Dict]) -> Dict[str, Any]:
        """Generate comprehensive statistics."""
        total_hosts = len(hosts)
        unique_ips = set()
        unique_fqdns = set()
        unique_ports = set()
        unique_schemes = set()
        
        for host_data in hosts.values():
            if host_data.get('ip'):
                unique_ips.add(host_data['ip'])
            
            for fqdn in host_data.get('fqdns', []):
                if fqdn:
                    unique_fqdns.add(fqdn)
            
            if host_data.get('port'):
                unique_ports.add(host_data['port'])
                
            if host_data.get('scheme'):
                unique_schemes.add(host_data['scheme'])
        
        # Generate service statistics
        unique_services = {}
        for service_instance in self._unique_service_instances:
            parts = service_instance.split('_')
            if len(parts) >= 3:
                service_name = '_'.join(parts[2:])
                unique_services[service_name] = unique_services.get(service_name, 0) + 1
        
        return {
            "hosts": {
                "total": total_hosts,
                "total_ips": len(unique_ips),
                "total_fqdns": len(unique_fqdns),
                "unique_ports": sorted(list(unique_ports)),
                "schemes_found": sorted(list(unique_schemes))
            },
            "services": {
                "unique_counts": dict(unique_services),
                "findings_counts": dict(self._service_findings_counts)
            },
            "vulnerabilities": {
                "total": self._total_vulnerabilities,
                "by_severity": dict(self._severity_counts),
                "by_type": dict(self._issue_type_counts)
            }
        }
    
    # Helper methods
    def _get_host_id(self) -> int:
        """Generate sequential host ID."""
        self._host_counter += 1
        return self._host_counter
    
    def _get_default_port(self, scheme: str) -> int:
        """Get default port for URL scheme."""
        scheme_ports = {
            'http': 80, 'https': 443, 'ftp': 21, 'ftps': 990, 'ssh': 22
        }
        return scheme_ports.get(scheme.lower(), 80)
    
    def _get_severity_label(self, severity: str) -> str:
        """Convert Burp severity text to standard label."""
        severity_map = {
            "Critical": "Critical", "High": "High", "Medium": "Medium",
            "Low": "Low", "Information": "None", "Info": "None", "": "None"
        }
        return severity_map.get(severity, "None")
    
    def _get_severity_numeric(self, severity: str) -> int:
        """Convert Burp severity text to numeric value."""
        severity_map = {
            "Critical": 4, "High": 3, "Medium": 2, "Low": 1,
            "Information": 0, "Info": 0, "": 0
        }
        return severity_map.get(severity, 0)
    
    def _format_datetime(self, datetime_str: str) -> str:
        """Format datetime to d-m-y h:m:s format."""
        try:
            dt = datetime.strptime(datetime_str, "%a %b %d %H:%M:%S %Z %Y")
            return dt.strftime("%d-%m-%Y %H:%M:%S")
        except (ValueError, TypeError):
            logger.debug(f"Failed to parse datetime: {datetime_str}")
            return datetime_str
    
    def _clean_html(self, html_content: str) -> str:
        """Remove HTML tags and clean up content for plain text storage."""
        if not html_content:
            return ""
        
        # Remove HTML tags and clean whitespace
        text = re.sub(r'<[^>]+>', '', html_content)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    def _extract_cwe_references(self, vuln_classifications: str) -> list:
        """Extract CWE references from vulnerability classifications."""
        if not vuln_classifications:
            return []
        
        cwe_matches = re.findall(r'CWE-(\d+)', vuln_classifications)
        return [f"CWE-{num}" for num in cwe_matches]