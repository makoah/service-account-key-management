from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential, ClientSecretCredential
import json
import os
from typing import Dict, List, Optional
from datetime import datetime
from config.settings import settings
from config.logging_config import get_app_logger, get_audit_logger
from utils.exceptions import KeyVaultError, ConfigurationError

class KeyVaultClient:
    def __init__(self):
        self.logger = get_app_logger(__name__)
        self.audit_logger = get_audit_logger()
        
        # Validate configuration
        if not settings.AZURE_KEYVAULT_URL:
            raise ConfigurationError("AZURE_KEYVAULT_URL is required")
        
        self.vault_url = settings.AZURE_KEYVAULT_URL
        
        # Initialize credential based on available configuration
        try:
            if all([settings.AZURE_CLIENT_ID, settings.AZURE_CLIENT_SECRET, settings.AZURE_TENANT_ID]):
                # Use service principal authentication
                self.credential = ClientSecretCredential(
                    tenant_id=settings.AZURE_TENANT_ID,
                    client_id=settings.AZURE_CLIENT_ID,
                    client_secret=settings.AZURE_CLIENT_SECRET
                )
                self.logger.info("Using service principal authentication for Key Vault")
            else:
                # Use default credential (managed identity, Azure CLI, etc.)
                self.credential = DefaultAzureCredential()
                self.logger.info("Using default credential authentication for Key Vault")
            
            self.client = SecretClient(vault_url=self.vault_url, credential=self.credential)
            
            # Test connection
            self._test_connection()
            
        except Exception as e:
            error_msg = f"Failed to initialize Key Vault client: {str(e)}"
            self.logger.error(error_msg)
            raise KeyVaultError(error_msg)
    
    def _test_connection(self):
        """Test Key Vault connection"""
        try:
            # Try to list secrets (this will fail if no permissions, but connection is tested)
            list(self.client.list_properties_of_secrets(max_page_size=1))
            self.logger.info("Key Vault connection test successful")
        except Exception as e:
            if "Forbidden" in str(e):
                self.logger.warning("Key Vault connection successful but may lack permissions")
            else:
                raise KeyVaultError(f"Key Vault connection test failed: {str(e)}")
    
    def store_key_pair(self, service_account: str, private_key: str, public_key: str, metadata: Dict, user_principal_name: str = None):
        """Store private key in Key Vault and metadata"""
        try:
            # Validate inputs
            if not service_account or not private_key or not public_key:
                raise KeyVaultError("Service account name and keys are required")
            
            # Add audit metadata
            audit_metadata = {
                **metadata,
                "created_by": user_principal_name,
                "created_at": datetime.now().isoformat(),
                "last_modified": datetime.now().isoformat()
            }
            
            # Store private key
            private_key_name = f"{service_account}-private-key"
            self.client.set_secret(private_key_name, private_key, tags={"type": "private-key", "service_account": service_account})
            
            # Store public key 
            public_key_name = f"{service_account}-public-key"
            self.client.set_secret(public_key_name, public_key, tags={"type": "public-key", "service_account": service_account})
            
            # Store metadata
            metadata_name = f"{service_account}-metadata"
            self.client.set_secret(metadata_name, json.dumps(audit_metadata), tags={"type": "metadata", "service_account": service_account})
            
            # Log the operation
            self.logger.info(f"Stored key pair for service account: {service_account}")
            self.audit_logger.info(f"KEY_STORED|{service_account}|{user_principal_name or 'system'}|SUCCESS")
            
            return True
            
        except Exception as e:
            error_msg = f"Failed to store key pair for {service_account}: {str(e)}"
            self.logger.error(error_msg)
            self.audit_logger.info(f"KEY_STORED|{service_account}|{user_principal_name or 'system'}|FAILED|{str(e)}")
            raise KeyVaultError(error_msg)
    
    def get_private_key(self, service_account: str, user_principal_name: str = None) -> str:
        """Retrieve private key from Key Vault"""
        try:
            secret_name = f"{service_account}-private-key"
            secret = self.client.get_secret(secret_name)
            
            # Log the access
            self.logger.info(f"Retrieved private key for service account: {service_account}")
            self.audit_logger.info(f"PRIVATE_KEY_ACCESSED|{service_account}|{user_principal_name or 'system'}|SUCCESS")
            
            return secret.value
            
        except Exception as e:
            error_msg = f"Failed to retrieve private key for {service_account}: {str(e)}"
            self.logger.error(error_msg)
            self.audit_logger.info(f"PRIVATE_KEY_ACCESSED|{service_account}|{user_principal_name or 'system'}|FAILED|{str(e)}")
            raise KeyVaultError(error_msg)
    
    def get_public_key(self, service_account: str, user_principal_name: str = None) -> str:
        """Retrieve public key from Key Vault"""
        try:
            secret_name = f"{service_account}-public-key"
            secret = self.client.get_secret(secret_name)
            
            # Log the access
            self.logger.info(f"Retrieved public key for service account: {service_account}")
            self.audit_logger.info(f"PUBLIC_KEY_ACCESSED|{service_account}|{user_principal_name or 'system'}|SUCCESS")
            
            return secret.value
            
        except Exception as e:
            error_msg = f"Failed to retrieve public key for {service_account}: {str(e)}"
            self.logger.error(error_msg)
            self.audit_logger.info(f"PUBLIC_KEY_ACCESSED|{service_account}|{user_principal_name or 'system'}|FAILED|{str(e)}")
            raise KeyVaultError(error_msg)
    
    def get_key_metadata(self, service_account: str) -> Dict:
        """Retrieve metadata for a service account"""
        try:
            secret_name = f"{service_account}-metadata"
            secret = self.client.get_secret(secret_name)
            return json.loads(secret.value)
        except Exception as e:
            self.logger.warning(f"Failed to retrieve metadata for {service_account}: {str(e)}")
            return {}
    
    def list_keys(self, user_filter: str = None) -> List[str]:
        """List all service accounts with stored keys, optionally filtered by user"""
        try:
            service_accounts = set()
            secrets = self.client.list_properties_of_secrets()
            
            for secret in secrets:
                if secret.name.endswith("-private-key"):
                    service_account = secret.name.replace("-private-key", "")
                    
                    # If user filter is specified, check metadata
                    if user_filter:
                        try:
                            metadata = self.get_key_metadata(service_account)
                            if metadata.get("created_by") == user_filter:
                                service_accounts.add(service_account)
                        except:
                            # If metadata can't be retrieved, include it anyway
                            service_accounts.add(service_account)
                    else:
                        service_accounts.add(service_account)
            
            result = list(service_accounts)
            self.logger.info(f"Listed {len(result)} service accounts")
            return result
            
        except Exception as e:
            error_msg = f"Failed to list keys: {str(e)}"
            self.logger.error(error_msg)
            raise KeyVaultError(error_msg)
    
    def delete_key(self, service_account: str, user_principal_name: str = None) -> bool:
        """Delete all secrets related to a service account"""
        try:
            secrets_to_delete = [
                f"{service_account}-private-key",
                f"{service_account}-public-key", 
                f"{service_account}-metadata"
            ]
            
            deleted_count = 0
            for secret_name in secrets_to_delete:
                try:
                    self.client.begin_delete_secret(secret_name)
                    deleted_count += 1
                except Exception as e:
                    if "NotFound" not in str(e):
                        self.logger.warning(f"Failed to delete {secret_name}: {str(e)}")
            
            # Log the operation
            self.logger.info(f"Deleted key pair for service account: {service_account} ({deleted_count} secrets)")
            self.audit_logger.info(f"KEY_DELETED|{service_account}|{user_principal_name or 'system'}|SUCCESS|{deleted_count}_secrets")
            
            return True
            
        except Exception as e:
            error_msg = f"Failed to delete keys for {service_account}: {str(e)}"
            self.logger.error(error_msg)
            self.audit_logger.info(f"KEY_DELETED|{service_account}|{user_principal_name or 'system'}|FAILED|{str(e)}")
            raise KeyVaultError(error_msg)
    
    def get_recent_activity(self) -> Optional[List[Dict]]:
        """Get recent key management activity"""
        try:
            activity = []
            secrets = self.client.list_properties_of_secrets()
            
            for secret in secrets:
                if secret.name.endswith("-metadata"):
                    service_account = secret.name.replace("-metadata", "")
                    
                    # Get metadata for more details
                    try:
                        metadata = self.get_key_metadata(service_account)
                        created_by = metadata.get("created_by", "Unknown")
                        created_at = metadata.get("created_at", "Unknown")
                    except:
                        created_by = "Unknown"
                        created_at = secret.created_on.strftime("%Y-%m-%d %H:%M:%S") if secret.created_on else "Unknown"
                    
                    activity.append({
                        "Service Account": service_account,
                        "Action": "Key Created/Updated",
                        "Created By": created_by,
                        "Date": created_at
                    })
            
            # Sort by date (newest first)
            return sorted(activity, key=lambda x: x["Date"], reverse=True)[:10]
            
        except Exception as e:
            self.logger.error(f"Failed to get recent activity: {str(e)}")
            return None