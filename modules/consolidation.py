import logging
import json
import re
from typing import Dict, Any, Optional, List
from pathlib import Path

logger = logging.getLogger(__name__)

class VulnerabilityConsolidator:
    """Consolidates Nessus vulnerabilities based on configurable rules."""
    
    def __init__(self, rules_file: str = "config/consolidation_rules.json"):
        """Initialize consolidator with rules file path."""
        self.rules_file = Path(rules_file)
        self.rules = []
        
    def consolidate(self, parsed_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Main consolidation function that processes parsed Nessus data.
        
        Args:
            parsed_data: The original parsed Nessus data
            
        Returns:
            Consolidated findings data or None if consolidation fails
        """
        logger.debug("Starting vulnerability consolidation")
        
        # Load consolidation rules
        if not self._load_rules():
            logger.warning("No consolidation rules loaded, skipping consolidation")
            return None
        
        logger.debug(f"Processing {len(parsed_data.get('vulnerabilities', {}))} vulnerabilities with {len(self.rules)} rules")
        
        # Apply rule matching
        matched_vulnerabilities = self.match_vulnerabilities(parsed_data)
        
        if not matched_vulnerabilities:
            logger.debug("No vulnerabilities matched consolidation rules")
            return self._create_basic_consolidated_structure(parsed_data)
        
        logger.debug(f"Matched {sum(len(matches) for matches in matched_vulnerabilities.values())} vulnerabilities across {len(matched_vulnerabilities)} rules")
        
        # Apply data aggregation
        consolidated_entries = self.aggregate_vulnerabilities(parsed_data, matched_vulnerabilities)
        
        return self._create_final_consolidated_structure(parsed_data, matched_vulnerabilities, consolidated_entries)
    
    def aggregate_vulnerabilities(self, parsed_data: Dict[str, Any], matched_vulns: Dict[str, List[str]]) -> Dict[str, Dict[str, Any]]:
        """
        Aggregate matched vulnerabilities according to rule specifications.
        
        Args:
            parsed_data: Original parsed Nessus data
            matched_vulns: Dictionary mapping rule names to plugin ID lists
            
        Returns:
            Dictionary of consolidated vulnerability entries
        """
        vulnerabilities = parsed_data.get('vulnerabilities', {})
        consolidated_entries = {}
        
        for rule_name, plugin_ids in matched_vulns.items():
            rule = next((r for r in self.rules if r['rule_name'] == rule_name), None)
            if not rule:
                continue
                
            logger.debug(f"Aggregating {len(plugin_ids)} vulnerabilities for rule '{rule_name}'")
            
            # Collect vulnerability data for aggregation
            vuln_data_list = [vulnerabilities[pid] for pid in plugin_ids if pid in vulnerabilities]
            
            if not vuln_data_list:
                continue
            
            # Aggregate metadata
            aggregated_metadata = self._aggregate_metadata(vuln_data_list, rule['aggregation'])
            
            # Consolidate solutions
            consolidated_solutions = self._consolidate_solutions(vuln_data_list)
            
            # Group affected services
            affected_services = self._group_affected_services(vuln_data_list, plugin_ids, rule['grouping_criteria'])
            
            # Build consolidated entry
            consolidated_entries[rule_name] = {
                "title": rule['title'],
                "severity": aggregated_metadata['severity'],
                "risk_factor": aggregated_metadata['risk_factor'],
                "cvss": aggregated_metadata['cvss'],
                "cvss3": aggregated_metadata['cvss3'],
                "consolidated_plugins": plugin_ids,
                "cve": aggregated_metadata['cve'],
                "cwe": aggregated_metadata['cwe'],
                "xref": aggregated_metadata['xref'],
                "see_also": aggregated_metadata['see_also'],
                "solutions": consolidated_solutions,
                "affected_services": affected_services
            }
        
        return consolidated_entries
    
    def _aggregate_metadata(self, vuln_data_list: List[Dict[str, Any]], aggregation_rules: Dict[str, str]) -> Dict[str, Any]:
        """Aggregate vulnerability metadata according to rules."""
        # Initialize aggregated data
        aggregated = {
            'severity': 0,
            'risk_factor': 'None',
            'cvss': {'base_score': 0, 'temporal_score': 0, 'vector': ''},
            'cvss3': {'base_score': 0, 'temporal_score': 0, 'vector': ''},
            'cve': [],
            'cwe': [],
            'xref': [],
            'see_also': []
        }
        
        # Severity hierarchy for comparison
        severity_order = {'None': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}
        risk_factors = []
        
        for vuln in vuln_data_list:
            # Collect severity data
            severity = vuln.get('severity', 0)
            risk_factor = vuln.get('risk_factor', 'None')
            
            if severity > aggregated['severity']:
                aggregated['severity'] = severity
            
            risk_factors.append(risk_factor)
            
            # Collect CVSS data (take maximum scores)
            cvss = vuln.get('cvss', {})
            cvss3 = vuln.get('cvss3', {})
            
            if cvss.get('base_score', 0) > aggregated['cvss']['base_score']:
                aggregated['cvss'] = cvss.copy()
            
            if cvss3.get('base_score', 0) > aggregated['cvss3']['base_score']:
                aggregated['cvss3'] = cvss3.copy()
            
            # Union collections (remove duplicates)
            for field in ['cve', 'cwe', 'xref', 'see_also']:
                values = vuln.get(field, [])
                if isinstance(values, list):
                    aggregated[field].extend(values)
        
        # Remove duplicates from lists
        for field in ['cve', 'cwe', 'xref', 'see_also']:
            aggregated[field] = list(set(aggregated[field]))
            aggregated[field] = [x for x in aggregated[field] if x]  # Remove empty strings
        
        # Set highest risk factor
        if risk_factors:
            risk_priority = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1, 'None': 0}
            aggregated['risk_factor'] = max(risk_factors, key=lambda x: risk_priority.get(x, 0))
        
        return aggregated
    
    def _consolidate_solutions(self, vuln_data_list: List[Dict[str, Any]]) -> List[str]:
        """Consolidate solutions from multiple vulnerabilities."""
        solutions = []
        
        for vuln in vuln_data_list:
            solution = vuln.get('solution', '').strip()
            if solution and solution not in solutions:
                solutions.append(solution)
        
        return solutions
    
    def _group_affected_services(self, vuln_data_list: List[Dict[str, Any]], plugin_ids: List[str], grouping_criteria: List[str]) -> Dict[str, Any]:
        """Group affected services according to grouping criteria."""
        services = {}
        
        for i, vuln in enumerate(vuln_data_list):
            plugin_id = plugin_ids[i] if i < len(plugin_ids) else str(i)
            affected_hosts = vuln.get('affected_hosts', {})
            
            for host_id, host_data in affected_hosts.items():
                ip = host_data.get('ip', '')
                fqdn = host_data.get('fqdn', '')
                ports = host_data.get('ports', [])
                plugin_output = host_data.get('plugin_output', '')
                
                # Create service keys based on grouping criteria
                for port in ports:
                    if 'port' in grouping_criteria:
                        service_key = f"{ip}:{port}" if 'ip' in grouping_criteria else port
                    else:
                        service_key = ip
                    
                    if service_key not in services:
                        services[service_key] = {
                            "ip": ip,
                            "fqdn": fqdn,
                            "port": port if ports else "",
                            "issues_found": [],
                            "plugin_outputs": {}
                        }
                    
                    # Add plugin-specific information
                    if plugin_id not in services[service_key]["issues_found"]:
                        services[service_key]["issues_found"].append(plugin_id)
                    
                    if plugin_output:
                        services[service_key]["plugin_outputs"][plugin_id] = plugin_output
        
        return services
    
    def _create_final_consolidated_structure(self, parsed_data: Dict[str, Any], matched_vulns: Dict[str, List[str]], consolidated_entries: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Create the final consolidated structure."""
        from datetime import datetime
        
        rule_names = [rule['rule_name'] for rule in self.rules]
        total_vulns = len(parsed_data.get('vulnerabilities', {}))
        total_matched = sum(len(matches) for matches in matched_vulns.values())
        
        return {
            "consolidation_metadata": {
                "rules_applied": rule_names,
                "original_plugins_count": total_vulns,
                "consolidated_count": total_matched,
                "consolidation_timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            },
            "consolidated_vulnerabilities": consolidated_entries
        }
    
    def match_vulnerabilities(self, parsed_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Match vulnerabilities against consolidation rules.
        
        Args:
            parsed_data: The original parsed Nessus data
            
        Returns:
            Dictionary mapping rule names to lists of matching plugin IDs
        """
        vulnerabilities = parsed_data.get('vulnerabilities', {})
        matched_vulns = {}
        
        for rule in self.rules:
            rule_name = rule['rule_name']
            logger.debug(f"Applying rule: {rule_name}")
            
            matches = self._apply_rule_filters(vulnerabilities, rule)
            
            if matches:
                matched_vulns[rule_name] = matches
                logger.debug(f"Rule '{rule_name}' matched {len(matches)} vulnerabilities: {matches}")
            else:
                logger.debug(f"Rule '{rule_name}' found no matches")
        
        return matched_vulns
    
    def _apply_rule_filters(self, vulnerabilities: Dict[str, Any], rule: Dict[str, Any]) -> List[str]:
        """Apply filtering logic for a single rule."""
        matches = []
        filters = rule['filters']
        
        for plugin_id, vuln_data in vulnerabilities.items():
            if self._matches_filter_criteria(vuln_data, filters):
                matches.append(plugin_id)
        
        return matches
    
    def _matches_filter_criteria(self, vuln_data: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """Check if a vulnerability matches the filter criteria."""
        # Get vulnerability properties
        family = vuln_data.get('family', '')
        name = vuln_data.get('name', '')
        
        # Check plugin families (if specified)
        plugin_families = filters.get('plugin_families', [])
        if plugin_families and family not in plugin_families:
            return False
        
        # Check exclude families
        exclude_families = filters.get('exclude_families', [])
        if exclude_families and family in exclude_families:
            return False
        
        # Check name patterns (if specified)
        name_patterns = filters.get('name_patterns', [])
        if name_patterns:
            pattern_matches = False
            for pattern in name_patterns:
                if re.search(pattern, name, re.IGNORECASE):
                    pattern_matches = True
                    break
            if not pattern_matches:
                return False
        
        # Check exclude name patterns
        exclude_name_patterns = filters.get('exclude_name_patterns', [])
        if exclude_name_patterns:
            for pattern in exclude_name_patterns:
                if re.search(pattern, name, re.IGNORECASE):
                    return False
        
        return True
    
    def _create_matched_consolidated_structure(self, parsed_data: Dict[str, Any], matched_vulns: Dict[str, List[str]]) -> Dict[str, Any]:
        """Create consolidated structure showing what was matched."""
        from datetime import datetime
        
        rule_names = [rule['rule_name'] for rule in self.rules]
        total_vulns = len(parsed_data.get('vulnerabilities', {}))
        total_matched = sum(len(matches) for matches in matched_vulns.values())
        
        # Create basic consolidated vulnerabilities structure for matched items
        consolidated_vulns = {}
        for rule_name, plugin_ids in matched_vulns.items():
            # Find the rule details
            rule = next((r for r in self.rules if r['rule_name'] == rule_name), None)
            if rule:
                consolidated_vulns[rule_name] = {
                    "title": rule['title'],
                    "matched_plugins": plugin_ids,
                    "match_count": len(plugin_ids)
                }
        
        return {
            "consolidation_metadata": {
                "rules_applied": rule_names,
                "original_plugins_count": total_vulns,
                "consolidated_count": total_matched,
                "consolidation_timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            },
            "consolidated_vulnerabilities": consolidated_vulns
        }
    
    def _load_rules(self) -> bool:
        """Load consolidation rules from config file."""
        try:
            # Check if rules file exists
            if not self.rules_file.exists():
                logger.warning(f"Rules file not found: {self.rules_file}")
                return False
            
            # Load and parse JSON
            with open(self.rules_file, 'r') as f:
                config_data = json.load(f)
            
            # Validate config structure
            if not self._validate_config_structure(config_data):
                return False
            
            # Extract enabled rules only
            all_rules = config_data.get('consolidation_rules', [])
            self.rules = [rule for rule in all_rules if rule.get('enabled', True)]
            
            logger.debug(f"Loaded {len(self.rules)} enabled consolidation rules")
            if len(self.rules) == 0:
                logger.warning("No enabled consolidation rules found")
                return False
                
            return True
            
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in rules file: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Error loading rules file: {str(e)}")
            return False
    
    def _validate_config_structure(self, config_data: Dict[str, Any]) -> bool:
        """Validate the basic structure of the configuration data."""
        try:
            # Check for required top-level key
            if 'consolidation_rules' not in config_data:
                logger.error("Config missing 'consolidation_rules' key")
                return False
            
            rules = config_data['consolidation_rules']
            if not isinstance(rules, list):
                logger.error("'consolidation_rules' must be a list")
                return False
            
            # Validate each rule structure
            for i, rule in enumerate(rules):
                if not self._validate_rule_structure(rule, i):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating config structure: {str(e)}")
            return False
    
    def _validate_rule_structure(self, rule: Dict[str, Any], index: int) -> bool:
        """Validate individual rule structure."""
        required_fields = ['rule_name', 'title', 'filters', 'grouping_criteria', 'aggregation']
        
        for field in required_fields:
            if field not in rule:
                logger.error(f"Rule {index}: Missing required field '{field}'")
                return False
        
        # Validate filters structure
        filters = rule['filters']
        if not isinstance(filters, dict):
            logger.error(f"Rule {index}: 'filters' must be a dictionary")
            return False
        
        # Validate grouping_criteria
        grouping = rule['grouping_criteria']
        if not isinstance(grouping, list):
            logger.error(f"Rule {index}: 'grouping_criteria' must be a list")
            return False
        
        # Validate aggregation
        aggregation = rule['aggregation']
        if not isinstance(aggregation, dict):
            logger.error(f"Rule {index}: 'aggregation' must be a dictionary")
            return False
        
        logger.debug(f"Rule {index} '{rule['rule_name']}' structure is valid")
        return True
    
    def _create_basic_consolidated_structure(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create basic consolidated structure showing rules were loaded."""
        from datetime import datetime
        
        rule_names = [rule['rule_name'] for rule in self.rules]
        total_vulns = len(parsed_data.get('vulnerabilities', {}))
        
        return {
            "consolidation_metadata": {
                "rules_applied": rule_names,
                "original_plugins_count": total_vulns,
                "consolidated_count": 0,  # Will be updated in actual consolidation
                "consolidation_timestamp": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
            },
            "consolidated_vulnerabilities": {}
        }
    
    def _create_empty_consolidated_structure(self) -> Dict[str, Any]:
        """Create empty consolidated structure for testing."""
        return {
            "consolidation_metadata": {
                "rules_applied": [],
                "original_plugins_count": 0,
                "consolidated_count": 0,
                "consolidation_timestamp": ""
            },
            "consolidated_vulnerabilities": {}
        }