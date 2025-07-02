import logging
from typing import Optional

def setup_logging(level: int = logging.INFO, format_string: Optional[str] = None) -> logging.Logger:
    """
    Configure and return logger instance for YANP.
    
    Args:
        level: Logging level (default: logging.INFO)
        format_string: Custom format string for log messages
        
    Returns:
        Configured logger instance
    """
    if format_string is None:
        format_string = '%(asctime)s - %(levelname)s - %(message)s'
    
    logging.basicConfig(
        format=format_string,
        level=level,
        datefmt='%d-%m-%y %H:%M:%S'
    )
    
    return logging.getLogger('yanp')

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module.
    
    Args:
        name: Logger name (typically __name__)
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)

def set_log_level(level: int) -> None:
    """
    Set the logging level for all YANP loggers.
    
    Args:
        level: New logging level
    """
    logging.getLogger('yanp').setLevel(level)
    
def disable_logging() -> None:
    """Disable all YANP logging."""
    logging.getLogger('yanp').disabled = True
    
def enable_logging() -> None:
    """Re-enable YANP logging."""
    logging.getLogger('yanp').disabled = False