from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
import json
import os
from typing import Dict, List, Optional

class KeyVaultClient:
    def __init__(self):
        self.vault_url = os.getenv("AZURE_KEYVAULT_URL")
        if not self.vault_url:
            raise ValueError("AZURE_KEYVAULT_URL environment variable is required")
        
        self.credential = DefaultAzureCredential()
        self.client = SecretClient(vault_url=self.vault_url, credential=self.credential)
    
    def store_key_pair(self, service_account: str, private_key: str, public_key: str, metadata: Dict):
        """Store private key in Key Vault and metadata"""
        try:
            # Store private key
            private_key_name = f"{service_account}-private-key"
            self.client.set_secret(private_key_name, private_key)
            
            # Store public key 
            public_key_name = f"{service_account}-public-key"
            self.client.set_secret(public_key_name, public_key)
            
            # Store metadata
            metadata_name = f"{service_account}-metadata"
            self.client.set_secret(metadata_name, json.dumps(metadata))
            
            return True
        except Exception as e:
            raise Exception(f"Failed to store key pair: {str(e)}")
    
    def get_private_key(self, service_account: str) -> str:
        """Retrieve private key from Key Vault"""
        try:
            secret_name = f"{service_account}-private-key"
            secret = self.client.get_secret(secret_name)
            return secret.value
        except Exception as e:
            raise Exception(f"Failed to retrieve private key: {str(e)}")
    
    def get_public_key(self, service_account: str) -> str:
        """Retrieve public key from Key Vault"""
        try:
            secret_name = f"{service_account}-public-key"
            secret = self.client.get_secret(secret_name)
            return secret.value
        except Exception as e:
            raise Exception(f"Failed to retrieve public key: {str(e)}")
    
    def get_key_metadata(self, service_account: str) -> Dict:
        """Retrieve metadata for a service account"""
        try:
            secret_name = f"{service_account}-metadata"
            secret = self.client.get_secret(secret_name)
            return json.loads(secret.value)
        except Exception as e:
            return {}
    
    def list_keys(self) -> List[str]:
        """List all service accounts with stored keys"""
        try:
            service_accounts = set()
            secrets = self.client.list_properties_of_secrets()
            
            for secret in secrets:
                if secret.name.endswith("-private-key"):
                    service_account = secret.name.replace("-private-key", "")
                    service_accounts.add(service_account)
            
            return list(service_accounts)
        except Exception as e:
            raise Exception(f"Failed to list keys: {str(e)}")
    
    def delete_key(self, service_account: str) -> bool:
        """Delete all secrets related to a service account"""
        try:
            secrets_to_delete = [
                f"{service_account}-private-key",
                f"{service_account}-public-key", 
                f"{service_account}-metadata"
            ]
            
            for secret_name in secrets_to_delete:
                try:
                    self.client.begin_delete_secret(secret_name)
                except:
                    # Continue if secret doesn't exist
                    pass
            
            return True
        except Exception as e:
            raise Exception(f"Failed to delete keys: {str(e)}")
    
    def get_recent_activity(self) -> Optional[List[Dict]]:
        """Get recent key management activity"""
        try:
            # This is a simplified version - in production you'd want proper audit logging
            activity = []
            secrets = self.client.list_properties_of_secrets()
            
            for secret in secrets:
                if secret.name.endswith("-metadata"):
                    service_account = secret.name.replace("-metadata", "")
                    activity.append({
                        "Service Account": service_account,
                        "Action": "Key Created/Updated",
                        "Date": secret.created_on.strftime("%Y-%m-%d %H:%M:%S") if secret.created_on else "Unknown"
                    })
            
            return sorted(activity, key=lambda x: x["Date"], reverse=True)[:10]
        except Exception as e:
            return None