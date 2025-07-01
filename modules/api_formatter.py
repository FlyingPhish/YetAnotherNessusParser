import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class APIFormatter:
    """Formats consolidated vulnerability findings for internal API consumption."""
    
    def __init__(self):
        """Initialize API formatter."""
        pass
    
    def format_for_api(self, consolidated_data: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
        """
        Transform consolidated findings into API-ready format.
        
        Args:
            consolidated_data: Output from VulnerabilityConsolidator
            
        Returns:
            List of API-ready finding dictionaries or None if no valid findings
        """
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
            
            # Format affected entities
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
        
        # logger.info(f"Successfully formatted {len(api_findings)} findings for API consumption")
        return api_findings
    
    def _format_affected_entities(self, affected_services: Dict[str, Any]) -> str:
        """
        Format affected services into HTML string for API consumption.
        
        Args:
            affected_services: Dictionary of affected services from consolidated data
            
        Returns:
            HTML-formatted string with affected entities
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
        
        # Format as HTML with line breaks
        entities_html = "<br />".join(unique_entities)
        return f"<p>{entities_html}</p>"