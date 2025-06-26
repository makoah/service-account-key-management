import os
from dotenv import load_dotenv
from typing import Optional

# Load environment variables from .env file
load_dotenv()

class Settings:
    """Application configuration settings"""
    
    # Azure Key Vault Configuration
    AZURE_KEYVAULT_URL: str = os.getenv("AZURE_KEYVAULT_URL", "")
    AZURE_CLIENT_ID: str = os.getenv("AZURE_CLIENT_ID", "")
    AZURE_CLIENT_SECRET: str = os.getenv("AZURE_CLIENT_SECRET", "")
    AZURE_TENANT_ID: str = os.getenv("AZURE_TENANT_ID", "")
    
    # Snowflake Configuration  
    SNOWFLAKE_ACCOUNT: str = os.getenv("SNOWFLAKE_ACCOUNT", "")
    SNOWFLAKE_USER: str = os.getenv("SNOWFLAKE_USER", "")
    SNOWFLAKE_PASSWORD: str = os.getenv("SNOWFLAKE_PASSWORD", "")
    SNOWFLAKE_WAREHOUSE: str = os.getenv("SNOWFLAKE_WAREHOUSE", "")
    SNOWFLAKE_DATABASE: str = os.getenv("SNOWFLAKE_DATABASE", "")
    SNOWFLAKE_SCHEMA: str = os.getenv("SNOWFLAKE_SCHEMA", "")
    
    # Active Directory Configuration
    AZURE_AD_CLIENT_ID: str = os.getenv("AZURE_AD_CLIENT_ID", "")
    AZURE_AD_CLIENT_SECRET: str = os.getenv("AZURE_AD_CLIENT_SECRET", "")
    AZURE_AD_TENANT_ID: str = os.getenv("AZURE_AD_TENANT_ID", "")
    
    # Application Configuration
    APP_NAME: str = os.getenv("APP_NAME", "Service Account Key Management")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    
    # Audit Logging
    AUDIT_LOG_RETENTION_DAYS: int = int(os.getenv("AUDIT_LOG_RETENTION_DAYS", "2555"))
    
    @classmethod
    def validate_required_settings(cls) -> list[str]:
        """Validate that all required settings are present"""
        missing_settings = []
        
        required_settings = [
            "AZURE_KEYVAULT_URL",
            "AZURE_CLIENT_ID", 
            "AZURE_CLIENT_SECRET",
            "AZURE_TENANT_ID",
            "SNOWFLAKE_ACCOUNT",
            "SNOWFLAKE_USER",
            "SNOWFLAKE_PASSWORD",
            "SECRET_KEY"
        ]
        
        for setting in required_settings:
            if not getattr(cls, setting):
                missing_settings.append(setting)
        
        return missing_settings
    
    @classmethod
    def is_development(cls) -> bool:
        """Check if running in development environment"""
        return os.getenv("ENVIRONMENT", "development").lower() == "development"

# Global settings instance
settings = Settings()