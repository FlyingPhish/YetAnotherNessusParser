import logging
from datetime import datetime
import nessus_file_reader as nfr

logger = logging.getLogger(__name__)

def format_datetime(dt) -> str:
    """Convert datetime object to string format"""
    return dt.strftime('%Y-%m-%d %H:%M:%S') if isinstance(dt, datetime) else str(dt)

def get_scan_summary(root) -> dict:
    """Extract high-level scan summary details"""
    try:
        scan_start = format_datetime(nfr.scan.scan_time_start(root))
        scan_end = format_datetime(nfr.scan.scan_time_end(root))
        scan_elapsed = nfr.scan.scan_time_elapsed(root)
        
        risk_totals = {
            'critical': 0, 'high': 0, 'medium': 0, 
            'low': 0, 'info': 0
        }
        
        for report_host in nfr.scan.report_hosts(root):
            host_name = nfr.host.report_host_name(report_host)
            
            # Update risk totals
            for risk, key in [('Critical', 'critical'), ('High', 'high'), 
                            ('Medium', 'medium'), ('Low', 'low'), ('None', 'info')]:
                count = nfr.host.number_of_plugins_per_risk_factor(report_host, risk)
                risk_totals[key] += count
                logger.debug(f"Host {host_name}: {risk}={count}")
        
        return {
            'report_name': nfr.scan.report_name(root),
            'target_hosts': nfr.scan.number_of_target_hosts(root),
            'scanned_hosts': nfr.scan.number_of_scanned_hosts(root),
            'credentialed_checks': nfr.scan.number_of_scanned_hosts_with_credentialed_checks_yes(root),
            **risk_totals,
            'scan_start': scan_start,
            'scan_end': scan_end,
            'scan_elapsed': scan_elapsed
        }
    except Exception as e:
        logger.error(f"Failed to extract scan summary: {str(e)}")
        return None

def get_detailed_scan_data(nessus_file: str) -> dict:
    """
    Extract detailed host and vulnerability information from nessus file
    
    Args:
        nessus_file (str): Path to nessus file
    
    Returns:
        dict: Detailed scan data including hosts, ports, and vulnerabilities
    """
    try:
        root = nfr.file.nessus_scan_file_root_element(nessus_file)
        hosts_data = {}
        vuln_tracking = {}
        
        for report_host in nfr.scan.report_hosts(root):
            host_name = nfr.host.report_host_name(report_host)
            
            # Debug log the original datetime format
            start_time = nfr.host.host_time_start(report_host)
            end_time = nfr.host.host_time_end(report_host)
            
            # Convert to string format if datetime object
            start_time_str = start_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(start_time, datetime) else str(start_time)
            end_time_str = end_time.strftime('%Y-%m-%d %H:%M:%S') if isinstance(end_time, datetime) else str(end_time)
            
            hosts_data[host_name] = {
                'os': nfr.host.detected_os(report_host),
                'start_time': start_time_str,
                'end_time': end_time_str,
                'ports': {},
                'vulnerabilities': {
                    'Critical': [],
                    'High': [],
                    'Medium': [],
                    'Low': [],
                    'None': []
                }
            }
            
            # Process each report item (vulnerability) for this host
            for report_item in nfr.host.report_items(report_host):
                plugin_id = nfr.plugin.report_item_value(report_item, 'pluginID')
                risk_factor = nfr.plugin.report_item_value(report_item, 'risk_factor')
                plugin_name = nfr.plugin.report_item_value(report_item, 'pluginName')
                port = report_item.get('port', 'No Port')
                protocol = report_item.get('protocol', 'No Protocol')
                port_key = f"{port}/{protocol}"
                
                # Create vulnerability entry
                vuln_entry = {
                    'plugin_id': plugin_id,
                    'name': plugin_name,
                    'risk_factor': risk_factor,
                    'port': port_key
                }
                
                # Track the vulnerability for this host
                if risk_factor in hosts_data[host_name]['vulnerabilities']:
                    hosts_data[host_name]['vulnerabilities'][risk_factor].append(vuln_entry)
                
                # Add port to host's ports if not already present
                if port_key not in hosts_data[host_name]['ports']:
                    hosts_data[host_name]['ports'][port_key] = []
                
                # Add vulnerability to port
                hosts_data[host_name]['ports'][port_key].append(vuln_entry)
                
                # Track unique vulnerabilities
                if plugin_id not in vuln_tracking:
                    vuln_tracking[plugin_id] = {
                        'name': plugin_name,
                        'risk_factor': risk_factor,
                        'affected_hosts': set(),
                        'affected_ports': set()
                    }
                vuln_tracking[plugin_id]['affected_hosts'].add(host_name)
                vuln_tracking[plugin_id]['affected_ports'].add(port_key)
        
        # Convert vuln_tracking sets to lists for JSON serialization
        for plugin_id in vuln_tracking:
            vuln_tracking[plugin_id]['affected_hosts'] = list(vuln_tracking[plugin_id]['affected_hosts'])
            vuln_tracking[plugin_id]['affected_ports'] = list(vuln_tracking[plugin_id]['affected_ports'])
            vuln_tracking[plugin_id]['host_count'] = len(vuln_tracking[plugin_id]['affected_hosts'])
        
        return {
            'hosts': hosts_data,
            'unique_vulnerabilities': vuln_tracking
        }
        
    except Exception as e:
        logging.error(f"Failed to extract detailed scan data: {str(e)}")
        return None