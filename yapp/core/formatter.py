import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class FormatterError(Exception):
    """Raised when API formatting fails."""
    pass

class APIFormatter:
    """Formats consolidated vulnerability findings for internal API consumption."""
    
    def __init__(self, entity_limit: Optional[int] = None):
        """
        Initialize API formatter.
        
        Args:
            entity_limit: Maximum number of affected entities per finding.
                         If None, no limit is applied.
        """
        self.entity_limit = entity_limit
        if self.entity_limit is not None and self.entity_limit < 1:
            raise FormatterError("Entity limit must be a positive integer")
    
    def format_for_api(self, consolidated_data: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """
        Transform consolidated findings into API-ready format.
        
        Args:
            consolidated_data: Output from VulnerabilityConsolidator
            
        Returns:
            List of API-ready finding dictionaries or None if no valid findings
            
        Raises:
            FormatterError: If formatting fails due to invalid input data
        """
        try:
            if not consolidated_data or not consolidated_data.get('consolidated_vulnerabilities'):
                logger.warning("No consolidated vulnerabilities found for API formatting")
                return None
            
            consolidated_vulns = consolidated_data['consolidated_vulnerabilities']
            api_findings = []
            
            for rule_name, rule_data in consolidated_vulns.items():
                # Only process findings with internal_vulnerability_id
                if 'internal_vulnerability_id' not in rule_data:
                    logger.debug(f"Skipping rule '{rule_name}' - no internal_vulnerability_id")
                    continue
                
                # Extract required data
                finding_id = rule_data['internal_vulnerability_id']
                affected_services = rule_data.get('affected_services', {})
                
                # Format affected entities with limit check
                affected_entities_html = self._format_affected_entities(affected_services)
                
                if not affected_entities_html:
                    logger.warning(f"No affected entities found for rule '{rule_name}', skipping")
                    continue
                
                # Create API finding entry
                api_finding = {
                    "type": "stock",
                    "finding_id": finding_id,
                    "affected_entities": affected_entities_html
                }
                
                api_findings.append(api_finding)
                logger.debug(f"Created API finding for rule '{rule_name}' with finding_id {finding_id}")
            
            if not api_findings:
                logger.warning("No API findings generated - no rules with internal_vulnerability_id found")
                return None
            
            logger.info(f"Successfully formatted {len(api_findings)} findings for API consumption")
            return api_findings
            
        except Exception as e:
            raise FormatterError(f"Failed to format consolidated data for API: {str(e)}")
    
    def format_for_custom_api(self, consolidated_data: Dict[str, Any], custom_format: Dict[str, str]) -> Optional[List[Dict[str, Any]]]:
        """
        Transform consolidated findings into custom API format.
        
        Args:
            consolidated_data: Output from VulnerabilityConsolidator
            custom_format: Dictionary mapping field names to custom field names
                          e.g., {"finding_id": "vulnerability_id", "affected_entities": "targets"}
            
        Returns:
            List of custom API-ready finding dictionaries or None if no valid findings
            
        Raises:
            FormatterError: If formatting fails
        """
        try:
            # Get standard API format first
            standard_findings = self.format_for_api(consolidated_data)
            
            if not standard_findings:
                return None
            
            # Convert to custom format
            custom_findings = []
            for finding in standard_findings:
                custom_finding = {}
                for standard_key, value in finding.items():
                    custom_key = custom_format.get(standard_key, standard_key)
                    custom_finding[custom_key] = value
                custom_findings.append(custom_finding)
            
            logger.info(f"Successfully formatted {len(custom_findings)} findings for custom API format")
            return custom_findings
            
        except Exception as e:
            raise FormatterError(f"Failed to format consolidated data for custom API: {str(e)}")
    
    def get_api_summary(self, api_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for API-formatted data.
        
        Args:
            api_data: List of API-ready findings
            
        Returns:
            Dictionary with summary statistics
        """
        if not api_data:
            return {
                "total_findings": 0,
                "unique_finding_ids": 0,
                "total_affected_entities": 0,
                "finding_ids_used": []
            }
        
        # Calculate statistics
        total_findings = len(api_data)
        finding_ids = [finding['finding_id'] for finding in api_data]
        unique_finding_ids = list(set(finding_ids))
        
        # Count total affected entities across all findings
        total_entities = 0
        for finding in api_data:
            affected_entities = finding.get('affected_entities', '')
            if affected_entities:
                # Count <br /> occurrences + 1 for total entities
                entity_count = affected_entities.count('<br />') + 1
                total_entities += entity_count
        
        return {
            "total_findings": total_findings,
            "unique_finding_ids": len(unique_finding_ids),
            "total_affected_entities": total_entities,
            "finding_ids_used": sorted(unique_finding_ids)
        }
    
    def validate_api_data(self, api_data: List[Dict[str, Any]]) -> bool:
        """
        Validate that API data has the expected structure.
        
        Args:
            api_data: List of API findings to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not isinstance(api_data, list):
            logger.error("API data must be a list")
            return False
        
        required_fields = ['type', 'finding_id', 'affected_entities']
        
        for i, finding in enumerate(api_data):
            if not isinstance(finding, dict):
                logger.error(f"Finding {i}: Must be a dictionary")
                return False
            
            for field in required_fields:
                if field not in finding:
                    logger.error(f"Finding {i}: Missing required field '{field}'")
                    return False
            
            # Validate field types
            if not isinstance(finding['finding_id'], (str, int)):
                logger.error(f"Finding {i}: 'finding_id' must be string or integer")
                return False
            
            if not isinstance(finding['affected_entities'], str):
                logger.error(f"Finding {i}: 'affected_entities' must be string")
                return False
        
        logger.debug(f"Validated {len(api_data)} API findings successfully")
        return True
    
    def _format_affected_entities(self, affected_services: Dict[str, Any]) -> str:
        """
        Format affected services into HTML string for API consumption.
        Applies entity limit if configured.
        
        Args:
            affected_services: Dictionary of affected services from consolidated data
            
        Returns:
            HTML-formatted string with affected entities or CSV reference if limit exceeded
        """
        if not affected_services:
            return ""
        
        entities = []
        
        for service_key, service_data in affected_services.items():
            ip = service_data.get('ip', '')
            fqdn = service_data.get('fqdn', '')
            port = service_data.get('port', '')
            
            # Add FQDN if available and not empty
            if fqdn and fqdn.strip():
                entities.append(fqdn.strip())
            
            # Add IP:port combination
            if ip:
                if port and port != '0':
                    entities.append(f"{ip}:{port}")
                else:
                    entities.append(ip)
        
        # Remove duplicates while preserving order
        unique_entities = []
        seen = set()
        for entity in entities:
            if entity not in seen:
                unique_entities.append(entity)
                seen.add(entity)
        
        if not unique_entities:
            return ""
        
        # Check entity limit if configured
        if self.entity_limit is not None and len(unique_entities) > self.entity_limit:
            logger.debug(f"Entity count ({len(unique_entities)}) exceeds limit ({self.entity_limit}), using CSV reference")
            return "<p>Please refer to external document named 'replaceMe'.csv</p>"
        
        # Format as HTML with line breaks
        entities_html = "<br />".join(unique_entities)
        return f"<p>{entities_html}</p>"
    
    def _format_affected_entities_plain(self, affected_services: Dict[str, Any]) -> List[str]:
        """
        Format affected services into plain list for alternative API formats.
        
        Args:
            affected_services: Dictionary of affected services from consolidated data
            
        Returns:
            List of affected entity strings
        """
        if not affected_services:
            return []
        
        entities = []
        
        for service_key, service_data in affected_services.items():
            ip = service_data.get('ip', '')
            fqdn = service_data.get('fqdn', '')
            port = service_data.get('port', '')
            
            # Add FQDN if available and not empty
            if fqdn and fqdn.strip():
                entities.append(fqdn.strip())
            
            # Add IP:port combination
            if ip:
                if port and port != '0':
                    entities.append(f"{ip}:{port}")
                else:
                    entities.append(ip)
        
        # Remove duplicates while preserving order
        unique_entities = []
        seen = set()
        for entity in entities:
            if entity not in seen:
                unique_entities.append(entity)
                seen.add(entity)
        
        return unique_entities