"""Custom exceptions for the application"""

class ServiceAccountKeyManagementError(Exception):
    """Base exception for the application"""
    pass

class AuthenticationError(ServiceAccountKeyManagementError):
    """Raised when authentication fails"""
    pass

class AuthorizationError(ServiceAccountKeyManagementError):
    """Raised when user lacks permission for an operation"""
    pass

class KeyVaultError(ServiceAccountKeyManagementError):
    """Raised when Azure Key Vault operations fail"""
    pass

class SnowflakeError(ServiceAccountKeyManagementError):
    """Raised when Snowflake operations fail"""
    pass

class KeyGenerationError(ServiceAccountKeyManagementError):
    """Raised when key generation fails"""
    pass

class ValidationError(ServiceAccountKeyManagementError):
    """Raised when input validation fails"""
    pass

class ConfigurationError(ServiceAccountKeyManagementError):
    """Raised when configuration is invalid or missing"""
    pass