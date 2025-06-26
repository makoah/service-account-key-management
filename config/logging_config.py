import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path
from config.settings import settings

def setup_logging():
    """Configure logging for the application and audit trails"""
    
    # Create logs directory if it doesn't exist
    logs_dir = Path("logs")
    logs_dir.mkdir(exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper()))
    
    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Console handler for development
    if settings.is_development():
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        root_logger.addHandler(console_handler)
    
    # Application log file handler
    app_log_file = logs_dir / "application.log"
    app_handler = logging.handlers.RotatingFileHandler(
        app_log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    app_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
    )
    app_handler.setFormatter(app_formatter)
    root_logger.addHandler(app_handler)
    
    # Set up audit logger separately
    setup_audit_logger()

def setup_audit_logger():
    """Set up dedicated audit logger for SOX compliance"""
    
    audit_logger = logging.getLogger('audit')
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False  # Don't propagate to root logger
    
    # Create audit logs directory
    audit_logs_dir = Path("logs/audit")
    audit_logs_dir.mkdir(parents=True, exist_ok=True)
    
    # Audit log file with date rotation
    today = datetime.now().strftime("%Y-%m-%d")
    audit_log_file = audit_logs_dir / f"audit_{today}.log"
    
    # Use TimedRotatingFileHandler for daily rotation
    audit_handler = logging.handlers.TimedRotatingFileHandler(
        audit_log_file,
        when='midnight',
        interval=1,
        backupCount=settings.AUDIT_LOG_RETENTION_DAYS,
        encoding='utf-8'
    )
    
    # Structured format for audit logs
    audit_formatter = logging.Formatter(
        '%(asctime)s|%(levelname)s|%(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    audit_handler.setFormatter(audit_formatter)
    audit_logger.addHandler(audit_handler)
    
    return audit_logger

def get_audit_logger():
    """Get the audit logger instance"""
    return logging.getLogger('audit')

def get_app_logger(name: str):
    """Get application logger for a specific module"""
    return logging.getLogger(name)