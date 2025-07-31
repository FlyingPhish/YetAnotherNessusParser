import logging
import json
import re
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime

logger = logging.getLogger(__name__)

class ConsolidationError(Exception):
    """Raised when consolidation processing fails."""
    pass

class VulnerabilityConsolidator:
    """Consolidates Nessus vulnerabilities based on configurable rules."""
    
    def __init__(self, rules_file: Optional[str] = None, enable_exclusion_logging: bool = False):
        """
        Initialize consolidator with rules file path.
        
        Args:
            rules_file: Path to custom consolidation rules file. 
                       If None, uses default bundled rules.
            enable_exclusion_logging: Enable detailed exclusion logging to file.
        """
        if rules_file:
            self.rules_file = Path(rules_file)
        else:
            self.rules_file = self._get_default_rules_path()
            
        self.rules = []
        self.exclusion_logger = None
        self.enable_exclusion_logging = enable_exclusion_logging
        
    def consolidate(self, parsed_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Main consolidation function that processes parsed Nessus data.
        
        Args:
            parsed_data: The original parsed Nessus data
            
        Returns:
            Consolidated findings data or None if no rules match
            
        Raises:
            ConsolidationError: If consolidation fails due to invalid rules or processing errors
        """
        logger.debug("Starting vulnerability consolidation")
        
        try:
            # Setup exclusion logging if enabled
            if self.enable_exclusion_logging:
                self._setup_exclusion_logging()
            
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
            
        except Exception as e:
            raise ConsolidationError(f"Consolidation failed: {str(e)}")
    
    def _setup_exclusion_logging(self):
        """Setup file-only logging for exclusion tracking."""
        # Create exclusion logger that only logs to file
        self.exclusion_logger = logging.getLogger('yapp.consolidation.exclusions')
        
        # Clear any existing handlers to prevent CLI output
        self.exclusion_logger.handlers.clear()
        self.exclusion_logger.propagate = False
        
        # Set log level
        self.exclusion_logger.setLevel(logging.INFO)
        
        # Create file handler with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = Path(f"yapp-exclusions-{timestamp}.log")
        
        file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
        file_handler.setLevel(logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        
        # Add handler to exclusion logger
        self.exclusion_logger.addHandler(file_handler)
        
        # Log session start
        self.exclusion_logger.info("=== Consolidation Exclusion Tracking Session Started ===")
        self.exclusion_logger.info(f"Rules file: {self.rules_file}")
    
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
            
            # Aggregate metadata (using smart defaults)
            aggregated_metadata = self._aggregate_metadata(vuln_data_list)
            
            # Consolidate solutions
            consolidated_solutions = self._consolidate_solutions(vuln_data_list)
            
            # Group affected services
            affected_services = self._group_affected_services(vuln_data_list, plugin_ids, rule['grouping_criteria'])
            
            # Create plugin mapping with names for readability
            consolidated_plugins = {}
            for plugin_id in plugin_ids:
                if plugin_id in vulnerabilities:
                    consolidated_plugins[plugin_id] = vulnerabilities[plugin_id].get('name', f'Plugin {plugin_id}')
                else:
                    consolidated_plugins[plugin_id] = f'Plugin {plugin_id}'
            
            # Build consolidated entry
            entry = {"title": rule['title']}

            # Add internal_vulnerability_id right after title if present
            if 'internal_vulnerability_id' in rule:
                entry["internal_vulnerability_id"] = rule['internal_vulnerability_id']

            # Add the rest of the fields
            entry.update({
                "severity": aggregated_metadata['severity'],
                "risk_factor": aggregated_metadata['risk_factor'],
                "cvss": aggregated_metadata['cvss'],
                "cvss3": aggregated_metadata['cvss3'],
                "consolidated_plugins": consolidated_plugins,
                "cve": aggregated_metadata['cve'],
                "cwe": aggregated_metadata['cwe'],
                "xref": aggregated_metadata['xref'],
                "see_also": aggregated_metadata['see_also'],
                "solutions": consolidated_solutions,
                "affected_services": affected_services
            })

            consolidated_entries[rule_name] = entry

        return consolidated_entries
    
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
    
    def _get_default_rules_path(self) -> Path:
        """Get path to default bundled consolidation rules."""
        # Get the package directory (where this file is located)
        package_dir = Path(__file__).parent.parent
        default_rules_path = package_dir / "config" / "default_rules.json"
        
        if not default_rules_path.exists():
            logger.warning(f"Default rules file not found at {default_rules_path}")
            # Fallback to looking in current working directory for development
            fallback_path = Path("yapp/config/default_rules.json")
            if fallback_path.exists():
                return fallback_path
            else:
                # Create an empty rules file path for graceful handling
                return Path("nonexistent_rules.json")
        
        return default_rules_path
    
    def _load_rules(self) -> bool:
        """Load consolidation rules from config file."""
        try:
            # Check if rules file exists
            if not self.rules_file.exists():
                logger.warning(f"Rules file not found: {self.rules_file}")
                return False
            
            # Load and parse JSON
            with open(self.rules_file, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            
            # Validate config structure
            if not self._validate_config_structure(config_data):
                return False
            
            # Extract enabled rules only
            all_rules = config_data.get('consolidation_rules', [])
            self.rules = [rule for rule in all_rules if rule.get('enabled', True)]
            
            logger.debug(f"Loaded {len(self.rules)} enabled consolidation rules from {self.rules_file}")
            if len(self.rules) == 0:
                logger.warning("No enabled consolidation rules found")
                return False
                
            return True
            
        except json.JSONDecodeError as e:
            raise ConsolidationError(f"Invalid JSON in rules file {self.rules_file}: {str(e)}")
        except Exception as e:
            raise ConsolidationError(f"Error loading rules file {self.rules_file}: {str(e)}")
    
    def _search_plugin_output(self, vuln_data: Dict[str, Any], patterns: List[str], require_all: bool = False) -> bool:
        """
        Search for patterns in plugin output across all affected hosts.
        
        Args:
            vuln_data: Vulnerability data containing affected_hosts
            patterns: List of regex patterns to search for
            require_all: If True, all patterns must match; if False, any pattern match is sufficient
            
        Returns:
            True if pattern(s) found according to require_all logic, False otherwise
        """
        if not patterns:
            return True  # No patterns to match means always pass
        
        affected_hosts = vuln_data.get('affected_hosts', {})
        if not affected_hosts:
            return False
        
        # Collect all plugin outputs from all affected hosts
        all_plugin_outputs = []
        for host_data in affected_hosts.values():
            plugin_output = host_data.get('plugin_output', '')
            if plugin_output:
                all_plugin_outputs.append(plugin_output)
        
        if not all_plugin_outputs:
            return False
        
        # Join all outputs for comprehensive searching
        combined_output = '\n'.join(all_plugin_outputs)
        
        matched_patterns = []
        for pattern in patterns:
            try:
                if re.search(pattern, combined_output, re.IGNORECASE | re.MULTILINE):
                    matched_patterns.append(pattern)
                    if not require_all:
                        # Early exit if we only need one match
                        return True
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{pattern}': {str(e)}")
                continue
        
        if require_all:
            return len(matched_patterns) == len(patterns)
        else:
            return len(matched_patterns) > 0
    
    def _aggregate_metadata(self, vuln_data_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate vulnerability metadata using smart defaults."""
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
            # Collect severity data (always take maximum)
            severity = vuln.get('severity', 0)
            risk_factor = vuln.get('risk_factor', 'None')
            
            if severity > aggregated['severity']:
                aggregated['severity'] = severity
            
            risk_factors.append(risk_factor)
            
            # Collect CVSS data (always take maximum scores)
            cvss = vuln.get('cvss', {})
            cvss3 = vuln.get('cvss3', {})
            
            if cvss.get('base_score', 0) > aggregated['cvss']['base_score']:
                aggregated['cvss'] = cvss.copy()
            
            if cvss3.get('base_score', 0) > aggregated['cvss3']['base_score']:
                aggregated['cvss3'] = cvss3.copy()
            
            # Union collections (always combine unique values)
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
            plugin_name = vuln.get('name', f'Plugin {plugin_id}')
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
                    
                    # Add plugin-specific information with human-readable format
                    plugin_info = {
                        "id": plugin_id,
                        "name": plugin_name
                    }
                    
                    if plugin_info not in services[service_key]["issues_found"]:
                        services[service_key]["issues_found"].append(plugin_info)
                    
                    if plugin_output:
                        services[service_key]["plugin_outputs"][plugin_id] = {
                            "name": plugin_name,
                            "output": plugin_output
                        }
        
        return services
    
    def _create_final_consolidated_structure(self, parsed_data: Dict[str, Any], matched_vulns: Dict[str, List[str]], consolidated_entries: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Create the final consolidated structure."""
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
    
    def _apply_rule_filters(self, vulnerabilities: Dict[str, Any], rule: Dict[str, Any]) -> List[str]:
        """Apply filtering logic for a single rule."""
        matches = []
        rule_name = rule['rule_name']
        filters = rule['filters']
        
        for plugin_id, vuln_data in vulnerabilities.items():
            if self._matches_filter_criteria(vuln_data, filters, rule_name, plugin_id):
                matches.append(plugin_id)
        
        return matches
    
    def _matches_filter_criteria(self, vuln_data: Dict[str, Any], filters: Dict[str, Any], rule_name: str, plugin_id: str) -> bool:
        """Check if a vulnerability matches the filter criteria with exclusion logging."""
        # Get vulnerability properties
        family = vuln_data.get('family', '')
        name = vuln_data.get('name', '')
        
        # First, check if name_patterns match (if specified)
        name_patterns = filters.get('name_patterns', [])
        name_patterns_matched = False
        
        if name_patterns:
            for pattern in name_patterns:
                try:
                    if re.search(pattern, name, re.IGNORECASE):
                        name_patterns_matched = True
                        break
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern}': {str(e)}")
                    continue
            
            # If name patterns specified but none matched, no need to check further
            if not name_patterns_matched:
                return False
        else:
            # If no name patterns specified, we'll consider it as potential match for exclusion logging
            name_patterns_matched = True
        
        # Now check other filters and log exclusions if name patterns matched
        
        # Check plugin families (if specified)
        plugin_families = filters.get('plugin_families', [])
        if plugin_families and family not in plugin_families:
            if name_patterns_matched and name_patterns:  # Only log if name patterns actually matched
                self._log_exclusion(rule_name, name, plugin_id, 'plugin_families', 
                                  f"family '{family}' not in required families {plugin_families}")
            return False
        
        # Check exclude families
        exclude_families = filters.get('exclude_families', [])
        if exclude_families and family in exclude_families:
            if name_patterns_matched:
                self._log_exclusion(rule_name, name, plugin_id, 'exclude_families', 
                                  f"family '{family}' matches excluded family in {exclude_families}")
            return False
        
        # Check exclude name patterns
        exclude_name_patterns = filters.get('exclude_name_patterns', [])
        if exclude_name_patterns:
            for pattern in exclude_name_patterns:
                try:
                    if re.search(pattern, name, re.IGNORECASE):
                        if name_patterns_matched:
                            self._log_exclusion(rule_name, name, plugin_id, 'exclude_name_patterns', 
                                              f"name matches exclusion pattern '{pattern}'")
                        return False
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern}': {str(e)}")
                    continue
        
        # Check plugin output patterns (if specified)
        plugin_output_patterns = filters.get('plugin_output_patterns', [])
        if plugin_output_patterns:
            require_all = filters.get('plugin_output_require_all', False)
            if not self._search_plugin_output(vuln_data, plugin_output_patterns, require_all):
                if name_patterns_matched:
                    mode = "all" if require_all else "any"
                    self._log_exclusion(rule_name, name, plugin_id, 'plugin_output_patterns', 
                                      f"plugin output doesn't match required patterns ({mode} of {plugin_output_patterns})")
                return False
        
        # Check exclude plugin output patterns
        exclude_plugin_output_patterns = filters.get('exclude_plugin_output_patterns', [])
        if exclude_plugin_output_patterns:
            require_all = filters.get('exclude_plugin_output_require_all', False)
            if self._search_plugin_output(vuln_data, exclude_plugin_output_patterns, require_all):
                if name_patterns_matched:
                    mode = "all" if require_all else "any"
                    self._log_exclusion(rule_name, name, plugin_id, 'exclude_plugin_output_patterns', 
                                      f"plugin output matches exclusion patterns ({mode} of {exclude_plugin_output_patterns})")
                return False
        
        return True
    
    def _log_exclusion(self, rule_name: str, vuln_name: str, plugin_id: str, filter_type: str, reason: str):
        """Log exclusion details to file."""
        if self.exclusion_logger:
            self.exclusion_logger.info(
                f"Rule '{rule_name}': Plugin {plugin_id} '{vuln_name}' matched name patterns but excluded by {filter_type} - {reason}"
            )
    
    def _validate_config_structure(self, config_data: Dict[str, Any]) -> bool:
        """Validate the basic structure of the configuration data."""
        try:
            # Check for required top-level key
            if 'consolidation_rules' not in config_data:
                raise ConsolidationError("Config missing 'consolidation_rules' key")
            
            rules = config_data['consolidation_rules']
            if not isinstance(rules, list):
                raise ConsolidationError("'consolidation_rules' must be a list")
            
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
        required_fields = ['rule_name', 'title', 'filters', 'grouping_criteria']
        
        for field in required_fields:
            if field not in rule:
                raise ConsolidationError(f"Rule {index}: Missing required field '{field}'")
        
        # Validate filters structure
        filters = rule['filters']
        if not isinstance(filters, dict):
            raise ConsolidationError(f"Rule {index}: 'filters' must be a dictionary")
        
        # Validate filter fields
        if not self._validate_filter_fields(filters, index):
            return False
        
        # Validate grouping_criteria
        grouping = rule['grouping_criteria']
        if not isinstance(grouping, list):
            raise ConsolidationError(f"Rule {index}: 'grouping_criteria' must be a list")
        
        # Validate grouping criteria values
        valid_grouping_options = ['ip', 'port', 'service']
        for criterion in grouping:
            if criterion not in valid_grouping_options:
                logger.warning(f"Rule {index}: Unknown grouping criterion '{criterion}'. Valid options: {valid_grouping_options}")
        
        logger.debug(f"Rule {index} '{rule['rule_name']}' structure is valid")
        return True
    
    def _validate_filter_fields(self, filters: Dict[str, Any], rule_index: int) -> bool:
        """Validate filter field types and content."""
        # Define expected field types
        list_fields = [
            'plugin_families', 'name_patterns', 'exclude_families', 
            'exclude_name_patterns', 'plugin_output_patterns', 
            'exclude_plugin_output_patterns'
        ]
        
        bool_fields = [
            'plugin_output_require_all', 'exclude_plugin_output_require_all'
        ]
        
        # Validate list fields
        for field in list_fields:
            if field in filters:
                value = filters[field]
                if not isinstance(value, list):
                    raise ConsolidationError(f"Rule {rule_index}: '{field}' must be a list, got {type(value).__name__}")
                
                # Validate regex patterns
                if 'patterns' in field:
                    if not self._validate_regex_patterns(value, field, rule_index):
                        return False
        
        # Validate boolean fields
        for field in bool_fields:
            if field in filters:
                value = filters[field]
                if not isinstance(value, bool):
                    raise ConsolidationError(f"Rule {rule_index}: '{field}' must be a boolean, got {type(value).__name__}")
        
        # Validate plugin families against known families
        if 'plugin_families' in filters:
            known_families = [
                'Service detection', 'Web Servers', 'Windows', 'General', 
                'CGI abuses', 'Firewalls', 'Databases', 'DNS', 'FTP',
                'SMTP problems', 'SNMP', 'Remote file access', 'Backdoors',
                'Peer-To-Peer File Sharing', 'Gain a shell remotely',
                'Denial of Service', 'Default Unix Accounts'
            ]
            
            for family in filters['plugin_families']:
                if family not in known_families:
                    logger.warning(f"Rule {rule_index}: Unknown plugin family '{family}'. This may still work but consider checking the spelling.")
        
        return True
    
    def _validate_regex_patterns(self, patterns: List[str], field_name: str, rule_index: int) -> bool:
        """Validate regex patterns for syntax errors."""
        for pattern in patterns:
            if not isinstance(pattern, str):
                raise ConsolidationError(f"Rule {rule_index}: All patterns in '{field_name}' must be strings")
            
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as e:
                raise ConsolidationError(f"Rule {rule_index}: Invalid regex pattern '{pattern}' in '{field_name}': {str(e)}")
        
        return True
    
    def _create_basic_consolidated_structure(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create basic consolidated structure showing rules were loaded."""
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