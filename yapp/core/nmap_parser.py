import logging
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

class NmapParser:
    """Parser for Nmap XML reports with structured output format."""
    
    def __init__(self, file_path: str):
        """Initialize parser with file path."""
        self.file_path = Path(file_path)
        self.tree = None
        self.root = None
        self._reset_counters()
        
    def parse(self, port_status_filter: str = "all") -> Optional[Dict[str, Any]]:
        """
        Parse Nmap XML file and return structured data.
        
        Args:
            port_status_filter: Filter by port status (open, closed, filtered, all)
        
        Returns:
            dict: Parsed Nmap data with context, stats, hosts, and services
            
        Raises:
            FileNotFoundError: If the Nmap file doesn't exist
            ET.ParseError: If the XML is malformed
            ValueError: If the file is not a valid Nmap file
        """
        # Validate input file
        self._validate_file()
        
        try:
            self.tree = ET.parse(self.file_path)
            self.root = self.tree.getroot()
            
            # Parse main sections
            context = self._parse_context()
            hosts_data = self._parse_hosts(port_status_filter)
            services_data = self._parse_services(port_status_filter)
            
            # Generate statistics after parsing all data
            stats = self._generate_statistics(hosts_data, services_data)
            
            return {
                "context": context,
                "stats": stats,
                "hosts": hosts_data,
                "services": services_data
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
        
        # Basic XML validation and check for Nmap format
        try:
            tree = ET.parse(self.file_path)
            root = tree.getroot()
            if root.tag != "nmaprun":
                raise ValueError(f"Not a valid Nmap XML file: {self.file_path}")
        except ET.ParseError as e:
            raise ET.ParseError(f"Invalid XML format in file: {self.file_path}")
    
    def _reset_counters(self):
        """Reset internal counters for fresh parsing."""
        self._host_counter = 0
        self._service_counts = defaultdict(int)
        self._port_counts = defaultdict(int)
        self._status_counts = defaultdict(int)
    
    def _parse_context(self) -> Dict[str, Any]:
        """Parse scan context information."""
        scan_info = self.root.find('scaninfo')
        run_stats = self.root.find('runstats/finished')
        
        # Get scan timestamps and command
        start_time = self.root.get('startstr', '')
        end_time = run_stats.get('timestr', '') if run_stats is not None else ''
        scan_args = self.root.get('args', '')
        scanner_version = self.root.get('version', '')
        
        return {
            "scanner": "nmap",
            "scanner_version": scanner_version,
            "scan_command": scan_args,
            "scan_start": start_time,
            "scan_end": end_time,
            "scan_duration": self._calculate_duration(),
            "scan_type": scan_info.get('type', '') if scan_info is not None else ''
        }
    
    def _parse_hosts(self, port_status_filter: str) -> Dict[str, Dict[str, Any]]:
        """Parse host information with sequential IDs."""
        hosts = {}
        
        for host_elem in self.root.findall('.//host'):
            host_id = str(self._get_host_id())
            
            # Extract host basic information
            ip = self._get_host_ip(host_elem)
            if not ip:
                continue  # Skip hosts without IP
                
            # Get hostname/FQDN
            hostname = self._get_host_hostname(host_elem)
            
            # Get host status
            status_elem = host_elem.find('status')
            host_status = status_elem.get('state', 'unknown') if status_elem is not None else 'unknown'
            
            # Process ports for this host
            ports_data = {}
            port_counts = {"open": 0, "closed": 0, "filtered": 0}
            
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_info = self._parse_port(port_elem, port_status_filter)
                    if port_info:
                        port_key = f"{port_info['protocol']}/{port_info['port_id']}"
                        ports_data[port_key] = port_info
                        port_counts[port_info['status']] += 1
            
            # Build host entry
            hosts[host_id] = {
                "ip": ip,
                "hostname": hostname,
                "status": host_status,
                "ports": ports_data,
                "port_summary": port_counts
            }
            
        return hosts
    
    def _parse_services(self, port_status_filter: str) -> Dict[str, Dict[str, Any]]:
        """Parse service information across all hosts."""
        services = {}
        service_id_counter = 0
        
        for host_elem in self.root.findall('.//host'):
            ip = self._get_host_ip(host_elem)
            hostname = self._get_host_hostname(host_elem)
            
            if not ip:
                continue
                
            ports_elem = host_elem.find('ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('port'):
                    port_info = self._parse_port(port_elem, port_status_filter)
                    if port_info and port_info.get('service_name'):
                        service_id_counter += 1
                        service_key = f"service_{service_id_counter}"
                        
                        services[service_key] = {
                            "host_ip": ip,
                            "host_hostname": hostname,
                            "port": f"{port_info['protocol']}/{port_info['port_id']}",
                            "port_status": port_info['status'],
                            "service_name": port_info['service_name'],
                            "service_details": port_info.get('service_details', {}),
                            "script_output": port_info.get('script_output', {})
                        }
                        
                        # Update service statistics
                        self._service_counts[port_info['service_name']] += 1
                        self._port_counts[f"{port_info['protocol']}/{port_info['port_id']}"] += 1
                        self._status_counts[port_info['status']] += 1
        
        return services
    
    def _parse_port(self, port_elem, port_status_filter: str) -> Optional[Dict[str, Any]]:
        """Parse individual port information."""
        port_id = port_elem.get("portid", "")
        protocol = port_elem.get("protocol", "").lower()
        
        # Get port state
        state_elem = port_elem.find("state")
        port_status = state_elem.get("state", "") if state_elem is not None else ""
        
        # Skip this port if it doesn't match the filter
        if port_status_filter != "all" and port_status != port_status_filter:
            return None
        
        # Get service information
        service_elem = port_elem.find("service")
        service_name = ""
        service_details = {}
        
        if service_elem is not None:
            service_name = service_elem.get("name", "")
            
            # Extract additional service details
            for attr in ["product", "version", "extrainfo", "method", "conf"]:
                if service_elem.get(attr):
                    service_details[attr] = service_elem.get(attr)
            
            # Add combined product/version field if both exist
            product = service_elem.get("product")
            version = service_elem.get("version")
            if product or version:
                combined = []
                if product:
                    combined.append(product)
                if version:
                    combined.append(version)
                service_details["combined_info"] = " ".join(combined)
        
        # Get script output if available
        script_output = {}
        scripts = port_elem.findall("script")
        for script in scripts:
            script_id = script.get("id", "")
            if script_id:
                script_output[script_id] = script.get("output", "")
        
        return {
            "port_id": port_id,
            "protocol": protocol,
            "status": port_status,
            "service_name": service_name,
            "service_details": service_details,
            "script_output": script_output
        }
    
    def _generate_statistics(self, hosts: Dict[str, Dict], services: Dict[str, Dict]) -> Dict[str, Any]:
        """Generate comprehensive statistics."""
        total_hosts = len(hosts)
        total_services = len(services)
        
        # Count unique IPs and hostnames
        unique_ips = set()
        unique_hostnames = set()
        host_status_counts = defaultdict(int)
        
        for host_data in hosts.values():
            ip = host_data.get('ip', '')
            hostname = host_data.get('hostname', '')
            status = host_data.get('status', 'unknown')
            
            if ip:
                unique_ips.add(ip)
            if hostname:
                unique_hostnames.add(hostname)
            
            host_status_counts[status] += 1
        
        return {
            "hosts": {
                "total": total_hosts,
                "unique_ips": len(unique_ips),
                "unique_hostnames": len(unique_hostnames),
                "by_status": dict(host_status_counts)
            },
            "ports": {
                "by_status": dict(self._status_counts),
                "by_port": dict(self._port_counts)
            },
            "services": {
                "total": total_services,
                "by_service": dict(self._service_counts)
            }
        }
    
    def _get_host_ip(self, host_elem) -> str:
        """Extract IP address from host element."""
        for address in host_elem.findall("address"):
            if address.get("addrtype") == "ipv4":
                return address.get("addr", "")
        return ""
    
    def _get_host_hostname(self, host_elem) -> str:
        """Extract hostname from host element."""
        hostnames = host_elem.find("hostnames")
        if hostnames is not None:
            hostname_elem = hostnames.find("hostname")
            if hostname_elem is not None:
                return hostname_elem.get("name", "")
        return ""
    
    def _get_host_id(self) -> int:
        """Generate sequential host ID."""
        self._host_counter += 1
        return self._host_counter
    
    def _calculate_duration(self) -> str:
        """Calculate scan duration from start/end times."""
        try:
            start_elem = self.root.get('start')
            finished = self.root.find('runstats/finished')
            
            if start_elem and finished is not None:
                start_time = int(start_elem)
                end_time = int(finished.get('time', 0))
                duration_seconds = end_time - start_time
                
                hours, remainder = divmod(duration_seconds, 3600)
                minutes, seconds = divmod(remainder, 60)
                
                if hours > 0:
                    return f"{hours}h {minutes}m {seconds}s"
                elif minutes > 0:
                    return f"{minutes}m {seconds}s"
                else:
                    return f"{seconds}s"
        except (ValueError, TypeError):
            return ""
        
        return ""