"""
yapp/core/nmap_comparator.py
Nmap scan comparison functionality - compares two Nmap XML scans to identify port/service differences.
"""

import logging
from typing import Dict, List, Tuple, Any

logger = logging.getLogger(__name__)


class NmapComparator:
    """
    Compares two Nmap scan results to identify port and service differences.
    Designed to work with YAPP's NmapParser output format.
    """
    
    def __init__(self):
        """Initialize Nmap comparator"""
        pass
    
    def compare(
        self, 
        first_scan: Dict[str, Any], 
        second_scan: Dict[str, Any],
        first_filename: str = "First Scan",
        second_filename: str = "Second Scan"
    ) -> Dict[str, Any]:
        """
        Compare two Nmap scan results and identify differences.
        
        Args:
            first_scan: First parsed Nmap scan data from NmapParser
            second_scan: Second parsed Nmap scan data from NmapParser
            first_filename: Display name for first scan
            second_filename: Display name for second scan
            
        Returns:
            dict: Comparison results with structure:
                {
                    'comparison_metadata': {...},
                    'comparison_data': [...],  # Row-by-row comparison
                    'statistics': {...}         # Merged statistics
                }
        """
        logger.info(f"Comparing {first_filename} vs {second_filename}")
        
        # Extract simplified port/service data for comparison
        first_data = self._extract_comparison_data(first_scan)
        second_data = self._extract_comparison_data(second_scan)
        
        # Perform comparison
        comparison_rows = self._compare_ports(first_data, second_data)
        
        # Merge data for statistics
        merged_data = self._merge_data(first_data, second_data)
        statistics = self._calculate_statistics(merged_data)
        
        # Build comparison metadata
        metadata = {
            'first_scan': first_filename,
            'second_scan': second_filename,
            'total_ips': len(set(list(first_data.keys()) + list(second_data.keys()))),
            'total_comparisons': len(comparison_rows),
            'differences_found': sum(1 for row in comparison_rows if row[5] == 'Yes')
        }
        
        return {
            'comparison_metadata': metadata,
            'comparison_data': comparison_rows,
            'statistics': statistics
        }
    
    def _extract_comparison_data(self, parsed_scan: Dict[str, Any]) -> Dict[str, List[Tuple[str, str]]]:
        """
        Extract simplified IP -> [(port/protocol, service)] mapping from parsed scan.
        
        Args:
            parsed_scan: Parsed Nmap data from NmapParser
            
        Returns:
            dict: Mapping of IP to list of (port/protocol, service) tuples
        """
        comparison_data = {}
        
        hosts = parsed_scan.get('hosts', {})
        for host_data in hosts.values():
            ip = host_data.get('ip', '')
            if not ip:
                continue
            
            ports_services = []
            ports = host_data.get('ports', {})
            
            for port_key, port_info in ports.items():
                # Only include open ports for comparison
                if port_info.get('status') == 'open':
                    # Format: "80/TCP"
                    port_protocol = f"{port_info['port_id']}/{port_info['protocol'].upper()}"
                    # Service name in uppercase, or UNKNOWN
                    service_name = port_info.get('service_name', 'UNKNOWN').upper() or 'UNKNOWN'
                    ports_services.append((port_protocol, service_name))
            
            if ports_services:
                comparison_data[ip] = ports_services
        
        return comparison_data
    
    def _compare_ports(
        self,
        first_data: Dict[str, List[Tuple[str, str]]],
        second_data: Dict[str, List[Tuple[str, str]]]
    ) -> List[Tuple[str, str, str, str, str, str]]:
        """
        Compare ports and services between two scans.
        
        Args:
            first_data: First scan data {ip: [(port, service), ...]}
            second_data: Second scan data {ip: [(port, service), ...]}
            
        Returns:
            List of tuples: (ip, port1, service1, port2, service2, differences)
        """
        comparison_rows = []
        all_ips = set(first_data.keys()) | set(second_data.keys())
        
        for ip in sorted(all_ips):
            # Convert lists to dicts for easier lookup
            first_ports = {port_service[0]: port_service for port_service in first_data.get(ip, [])}
            second_ports = {port_service[0]: port_service for port_service in second_data.get(ip, [])}
            
            all_ports = set(first_ports.keys()) | set(second_ports.keys())
            
            for port in sorted(all_ports):
                port1, service1 = first_ports.get(port, ('N/A', 'N/A'))
                port2, service2 = second_ports.get(port, ('N/A', 'N/A'))
                
                # Check if there are differences
                differences = 'Yes' if (port1, service1) != (port2, service2) else 'No'
                
                comparison_rows.append((ip, port1, service1, port2, service2, differences))
        
        return comparison_rows
    
    def _merge_data(
        self,
        first_data: Dict[str, List[Tuple[str, str]]],
        second_data: Dict[str, List[Tuple[str, str]]]
    ) -> Dict[str, List[Tuple[str, str]]]:
        """
        Merge data from both scans for statistics generation.
        
        Args:
            first_data: First scan data
            second_data: Second scan data
            
        Returns:
            dict: Merged data with unique port/service combinations per IP
        """
        merged_data = first_data.copy()
        
        for ip, ports_services in second_data.items():
            if ip in merged_data:
                # Combine unique port/service tuples for the same IP
                merged_data[ip] = list(set(merged_data[ip] + ports_services))
            else:
                merged_data[ip] = ports_services
        
        return merged_data
    
    def _calculate_statistics(
        self, 
        merged_data: Dict[str, List[Tuple[str, str]]]
    ) -> Dict[str, Any]:
        """
        Calculate statistics from merged scan data.
        
        Args:
            merged_data: Merged data from both scans
            
        Returns:
            dict: Statistics including service counts and port counts
        """
        service_counts = {}  # service -> {count: int, ips: set}
        port_counts = {}     # port -> count
        total_ips = len(merged_data)
        
        for ip, ports_services in merged_data.items():
            for port, service in ports_services:
                # Count services
                if service not in service_counts:
                    service_counts[service] = {"count": 0, "ips": set()}
                service_counts[service]["count"] += 1
                service_counts[service]["ips"].add(ip)
                
                # Count ports
                port_counts[port] = port_counts.get(port, 0) + 1
        
        # Convert IP sets to counts
        for service in service_counts:
            service_counts[service]["ips"] = len(service_counts[service]["ips"])
        
        return {
            "service_counts": service_counts,
            "port_counts": port_counts,
            "total_ips": total_ips
        }