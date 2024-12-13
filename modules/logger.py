import logging

def setup_logging(level=logging.INFO):
    """Configure and return logger instance"""
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s',
        level=level,
        datefmt='%d-%m-%y %H:%M:%S'
    )
    return logging.getLogger(__name__)