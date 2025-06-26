import logging
import json
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
        logger.info("Starting vulnerability consolidation")
        
        # Load consolidation rules
        if not self._load_rules():
            logger.warning("No consolidation rules loaded, skipping consolidation")
            return None
        
        logger.info(f"Processing {len(parsed_data.get('vulnerabilities', {}))} vulnerabilities with {len(self.rules)} rules")
        
        # TODO: Implement actual consolidation logic in subsequent tasks
        # For now, return a basic structure showing rules were loaded
        return self._create_basic_consolidated_structure(parsed_data)
    
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
            
            logger.info(f"Loaded {len(self.rules)} enabled consolidation rules")
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