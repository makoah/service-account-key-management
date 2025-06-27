import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum
from config.settings import settings
from config.logging_config import get_audit_logger
from utils.exceptions import ValidationError

class AuditEventType(Enum):
    """Enumeration of audit event types for SOX compliance"""
    USER_LOGIN = "USER_LOGIN"
    USER_LOGOUT = "USER_LOGOUT"
    ACCESS_GRANTED = "ACCESS_GRANTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    KEY_GENERATED = "KEY_GENERATED"
    KEY_STORED = "KEY_STORED"
    KEY_RETRIEVED = "KEY_RETRIEVED"
    KEY_DELETED = "KEY_DELETED"
    KEY_ROTATED = "KEY_ROTATED"
    PRIVATE_KEY_ACCESSED = "PRIVATE_KEY_ACCESSED"
    PUBLIC_KEY_ACCESSED = "PUBLIC_KEY_ACCESSED"
    PUBLIC_KEY_DOWNLOADED = "PUBLIC_KEY_DOWNLOADED"
    SNOWFLAKE_KEY_UPDATE = "SNOWFLAKE_KEY_UPDATE"
    SNOWFLAKE_KEY_REMOVED = "SNOWFLAKE_KEY_REMOVED"
    CONFIGURATION_CHANGED = "CONFIGURATION_CHANGED"
    SYSTEM_ERROR = "SYSTEM_ERROR"
    SECURITY_VIOLATION = "SECURITY_VIOLATION"

class AuditSeverity(Enum):
    """Audit event severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class SOXAuditLogger:
    """
    SOX-compliant audit logger with structured logging for key management operations
    
    This logger provides comprehensive audit trails required for SOX compliance,
    including user identification, timestamps, and detailed operation tracking.
    """
    
    def __init__(self):
        self.audit_logger = get_audit_logger()
        self.app_logger = logging.getLogger(__name__)
        
    def log_event(self, 
                  event_type: AuditEventType,
                  user_principal_name: str,
                  resource: str = None,
                  action_result: str = "SUCCESS",
                  severity: AuditSeverity = AuditSeverity.MEDIUM,
                  additional_data: Dict[str, Any] = None,
                  error_message: str = None) -> bool:
        """
        Log a structured audit event
        
        Args:
            event_type: Type of event being logged
            user_principal_name: User performing the action
            resource: Resource being acted upon (e.g., service account name)
            action_result: Result of the action (SUCCESS, FAILED, DENIED)
            severity: Severity level of the event
            additional_data: Additional context data
            error_message: Error message if action failed
            
        Returns:
            True if logged successfully, False otherwise
        """
        try:
            # Build structured audit record
            audit_record = {
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "event_type": event_type.value,
                "user_principal_name": user_principal_name or "SYSTEM",
                "resource": resource,
                "action_result": action_result,
                "severity": severity.value,
                "session_id": self._get_session_id(),
                "source_ip": self._get_source_ip(),
                "user_agent": self._get_user_agent(),
                "application": settings.APP_NAME,
                "environment": settings.ENVIRONMENT
            }
            
            # Add additional data if provided
            if additional_data:
                audit_record["additional_data"] = additional_data
            
            # Add error message if provided
            if error_message:
                audit_record["error_message"] = error_message
            
            # Log in structured format
            structured_message = self._format_audit_message(audit_record)
            
            # Use appropriate log level based on severity and result
            if action_result == "FAILED" or severity in [AuditSeverity.HIGH, AuditSeverity.CRITICAL]:
                self.audit_logger.error(structured_message)
            elif action_result == "DENIED" or severity == AuditSeverity.MEDIUM:
                self.audit_logger.warning(structured_message)
            else:
                self.audit_logger.info(structured_message)
            
            return True
            
        except Exception as e:
            self.app_logger.error(f"Failed to log audit event: {str(e)}")
            return False
    
    def log_user_authentication(self, user_principal_name: str, success: bool, error_message: str = None):
        """Log user authentication attempts"""
        self.log_event(
            event_type=AuditEventType.USER_LOGIN,
            user_principal_name=user_principal_name,
            action_result="SUCCESS" if success else "FAILED",
            severity=AuditSeverity.MEDIUM if success else AuditSeverity.HIGH,
            error_message=error_message
        )
    
    def log_access_control(self, user_principal_name: str, permission: str, granted: bool, resource: str = None):
        """Log access control decisions"""
        self.log_event(
            event_type=AuditEventType.ACCESS_GRANTED if granted else AuditEventType.ACCESS_DENIED,
            user_principal_name=user_principal_name,
            resource=resource,
            action_result="SUCCESS" if granted else "DENIED",
            severity=AuditSeverity.LOW if granted else AuditSeverity.MEDIUM,
            additional_data={"permission": permission}
        )
    
    def log_key_operation(self, 
                         operation: str,
                         service_account: str,
                         user_principal_name: str,
                         success: bool,
                         key_size: int = None,
                         error_message: str = None):
        """Log key management operations"""
        
        # Map operation to event type
        operation_map = {
            "GENERATED": AuditEventType.KEY_GENERATED,
            "STORED": AuditEventType.KEY_STORED,
            "RETRIEVED": AuditEventType.KEY_RETRIEVED,
            "DELETED": AuditEventType.KEY_DELETED,
            "ROTATED": AuditEventType.KEY_ROTATED
        }
        
        event_type = operation_map.get(operation.upper(), AuditEventType.KEY_STORED)
        
        additional_data = {}
        if key_size:
            additional_data["key_size_bits"] = key_size
        
        self.log_event(
            event_type=event_type,
            user_principal_name=user_principal_name,
            resource=service_account,
            action_result="SUCCESS" if success else "FAILED",
            severity=AuditSeverity.MEDIUM,
            additional_data=additional_data if additional_data else None,
            error_message=error_message
        )
    
    def log_key_access(self, 
                      access_type: str,
                      service_account: str,
                      user_principal_name: str,
                      success: bool,
                      error_message: str = None):
        """Log key access operations (private/public key retrieval)"""
        
        event_type = AuditEventType.PRIVATE_KEY_ACCESSED if access_type.upper() == "PRIVATE" else AuditEventType.PUBLIC_KEY_ACCESSED
        
        # Private key access is more sensitive
        severity = AuditSeverity.HIGH if access_type.upper() == "PRIVATE" else AuditSeverity.MEDIUM
        
        self.log_event(
            event_type=event_type,
            user_principal_name=user_principal_name,
            resource=service_account,
            action_result="SUCCESS" if success else "FAILED",
            severity=severity,
            additional_data={"access_type": access_type},
            error_message=error_message
        )
    
    def log_snowflake_operation(self,
                               operation: str,
                               snowflake_user: str,
                               user_principal_name: str,
                               success: bool,
                               error_message: str = None):
        """Log Snowflake-related operations"""
        
        event_type = AuditEventType.SNOWFLAKE_KEY_UPDATE if operation.upper() == "UPDATE" else AuditEventType.SNOWFLAKE_KEY_REMOVED
        
        self.log_event(
            event_type=event_type,
            user_principal_name=user_principal_name,
            resource=snowflake_user,
            action_result="SUCCESS" if success else "FAILED",
            severity=AuditSeverity.MEDIUM,
            additional_data={"snowflake_operation": operation},
            error_message=error_message
        )
    
    def log_security_violation(self,
                              violation_type: str,
                              user_principal_name: str,
                              details: str,
                              resource: str = None):
        """Log security violations for immediate attention"""
        self.log_event(
            event_type=AuditEventType.SECURITY_VIOLATION,
            user_principal_name=user_principal_name,
            resource=resource,
            action_result="VIOLATION",
            severity=AuditSeverity.CRITICAL,
            additional_data={
                "violation_type": violation_type,
                "details": details
            }
        )
    
    def log_system_error(self,
                        error_type: str,
                        error_message: str,
                        user_principal_name: str = None,
                        resource: str = None):
        """Log system errors for troubleshooting"""
        self.log_event(
            event_type=AuditEventType.SYSTEM_ERROR,
            user_principal_name=user_principal_name or "SYSTEM",
            resource=resource,
            action_result="ERROR",
            severity=AuditSeverity.HIGH,
            additional_data={"error_type": error_type},
            error_message=error_message
        )
    
    def _format_audit_message(self, audit_record: Dict[str, Any]) -> str:
        """Format audit record as structured message"""
        try:
            # Use pipe-separated format for easy parsing
            base_message = (
                f"{audit_record['event_type']}|"
                f"{audit_record['user_principal_name']}|"
                f"{audit_record['resource'] or 'N/A'}|"
                f"{audit_record['action_result']}|"
                f"{audit_record['severity']}"
            )
            
            # Add additional context
            if audit_record.get('error_message'):
                base_message += f"|ERROR:{audit_record['error_message']}"
            
            if audit_record.get('additional_data'):
                additional_json = json.dumps(audit_record['additional_data'])
                base_message += f"|DATA:{additional_json}"
            
            # Add full JSON record for complete context
            full_json = json.dumps(audit_record)
            return f"{base_message}|JSON:{full_json}"
            
        except Exception as e:
            # Fallback to simple format if JSON serialization fails
            return (
                f"{audit_record.get('event_type', 'UNKNOWN')}|"
                f"{audit_record.get('user_principal_name', 'UNKNOWN')}|"
                f"{audit_record.get('resource', 'N/A')}|"
                f"{audit_record.get('action_result', 'UNKNOWN')}|"
                f"FORMAT_ERROR:{str(e)}"
            )
    
    def _get_session_id(self) -> Optional[str]:
        """Get current session ID (if available from Streamlit)"""
        try:
            import streamlit as st
            return st.session_state.get('session_id', 'unknown')
        except:
            return 'unknown'
    
    def _get_source_ip(self) -> Optional[str]:
        """Get source IP address (if available)"""
        try:
            # In a production environment, this would get the real client IP
            # For local development, return localhost
            return "127.0.0.1" if settings.is_development() else "unknown"
        except:
            return 'unknown'
    
    def _get_user_agent(self) -> Optional[str]:
        """Get user agent (if available)"""
        try:
            # In a web application, this would get the actual user agent
            return "Streamlit-App"
        except:
            return 'unknown'
    
    def generate_audit_report(self, 
                             start_date: datetime = None,
                             end_date: datetime = None,
                             user_filter: str = None,
                             event_type_filter: AuditEventType = None) -> Dict[str, Any]:
        """
        Generate audit report for compliance purposes
        
        Args:
            start_date: Start date for report
            end_date: End date for report  
            user_filter: Filter by specific user
            event_type_filter: Filter by event type
            
        Returns:
            Dictionary containing audit report data
        """
        try:
            # This is a placeholder for report generation
            # In a full implementation, this would query audit logs
            # and generate comprehensive reports
            
            report = {
                "report_generated": datetime.utcnow().isoformat() + "Z",
                "report_period": {
                    "start_date": start_date.isoformat() if start_date else None,
                    "end_date": end_date.isoformat() if end_date else None
                },
                "filters": {
                    "user_filter": user_filter,
                    "event_type_filter": event_type_filter.value if event_type_filter else None
                },
                "summary": {
                    "total_events": 0,
                    "events_by_type": {},
                    "events_by_user": {},
                    "security_violations": 0,
                    "failed_operations": 0
                },
                "note": "Report generation requires implementation of audit log querying"
            }
            
            return report
            
        except Exception as e:
            self.app_logger.error(f"Failed to generate audit report: {str(e)}")
            return {"error": str(e)}

# Global audit logger instance
sox_audit_logger = SOXAuditLogger()

# Convenience functions for common audit operations
def audit_user_login(user_principal_name: str, success: bool, error_message: str = None):
    """Convenience function for logging user authentication"""
    sox_audit_logger.log_user_authentication(user_principal_name, success, error_message)

def audit_access_control(user_principal_name: str, permission: str, granted: bool, resource: str = None):
    """Convenience function for logging access control decisions"""
    sox_audit_logger.log_access_control(user_principal_name, permission, granted, resource)

def audit_key_operation(operation: str, service_account: str, user_principal_name: str, success: bool, **kwargs):
    """Convenience function for logging key operations"""
    sox_audit_logger.log_key_operation(operation, service_account, user_principal_name, success, **kwargs)

def audit_security_violation(violation_type: str, user_principal_name: str, details: str, resource: str = None):
    """Convenience function for logging security violations"""
    sox_audit_logger.log_security_violation(violation_type, user_principal_name, details, resource)