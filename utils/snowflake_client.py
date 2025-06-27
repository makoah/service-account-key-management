import snowflake.connector
from typing import Optional, Dict, Any, List
from config.settings import settings
from config.logging_config import get_app_logger, get_audit_logger
from utils.exceptions import SnowflakeError, ConfigurationError

class SnowflakeClient:
    """Snowflake client for managing user public keys"""
    
    def __init__(self):
        self.logger = get_app_logger(__name__)
        self.audit_logger = get_audit_logger()
        
        # Validate configuration
        required_settings = [
            settings.SNOWFLAKE_ACCOUNT,
            settings.SNOWFLAKE_USER,
            settings.SNOWFLAKE_PASSWORD,
            settings.SNOWFLAKE_WAREHOUSE,
            settings.SNOWFLAKE_DATABASE,
            settings.SNOWFLAKE_SCHEMA
        ]
        
        if not all(required_settings):
            missing = [name for name, value in [
                ("SNOWFLAKE_ACCOUNT", settings.SNOWFLAKE_ACCOUNT),
                ("SNOWFLAKE_USER", settings.SNOWFLAKE_USER),
                ("SNOWFLAKE_PASSWORD", settings.SNOWFLAKE_PASSWORD),
                ("SNOWFLAKE_WAREHOUSE", settings.SNOWFLAKE_WAREHOUSE),
                ("SNOWFLAKE_DATABASE", settings.SNOWFLAKE_DATABASE),
                ("SNOWFLAKE_SCHEMA", settings.SNOWFLAKE_SCHEMA)
            ] if not value]
            raise ConfigurationError(f"Missing Snowflake configuration: {', '.join(missing)}")
        
        self.connection_params = {
            'account': settings.SNOWFLAKE_ACCOUNT,
            'user': settings.SNOWFLAKE_USER,
            'password': settings.SNOWFLAKE_PASSWORD,
            'warehouse': settings.SNOWFLAKE_WAREHOUSE,
            'database': settings.SNOWFLAKE_DATABASE,
            'schema': settings.SNOWFLAKE_SCHEMA
        }
        
        # Test connection on initialization
        self._test_connection()
    
    def _test_connection(self):
        """Test Snowflake connection"""
        try:
            with snowflake.connector.connect(**self.connection_params) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT CURRENT_VERSION()")
                version = cursor.fetchone()[0]
                self.logger.info(f"Snowflake connection test successful. Version: {version}")
                
        except Exception as e:
            error_msg = f"Snowflake connection test failed: {str(e)}"
            self.logger.error(error_msg)
            raise SnowflakeError(error_msg)
    
    def _get_connection(self):
        """Get a new Snowflake connection"""
        try:
            return snowflake.connector.connect(**self.connection_params)
        except Exception as e:
            error_msg = f"Failed to connect to Snowflake: {str(e)}"
            self.logger.error(error_msg)
            raise SnowflakeError(error_msg)
    
    def update_user_public_key(self, snowflake_username: str, public_key: str, requesting_user: str = None) -> bool:
        """Update a Snowflake user's public key for key-pair authentication"""
        try:
            # Validate inputs
            if not snowflake_username or not public_key:
                raise SnowflakeError("Snowflake username and public key are required")
            
            # Check if user exists first
            if not self.user_exists(snowflake_username):
                raise SnowflakeError(f"Snowflake user '{snowflake_username}' does not exist")
            
            # Clean the public key (remove any headers/footers and newlines)
            cleaned_public_key = self._clean_public_key(public_key)
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Update user's RSA public key
                alter_user_sql = f"""
                ALTER USER {snowflake_username} 
                SET RSA_PUBLIC_KEY='{cleaned_public_key}'
                """
                
                cursor.execute(alter_user_sql)
                
                # Verify the update
                cursor.execute(f"DESCRIBE USER {snowflake_username}")
                user_info = cursor.fetchall()
                
                # Check if RSA_PUBLIC_KEY was set
                rsa_key_set = any(
                    row[0] == 'RSA_PUBLIC_KEY' and row[1] 
                    for row in user_info
                )
                
                if not rsa_key_set:
                    raise SnowflakeError(f"Failed to verify public key update for user {snowflake_username}")
                
                self.logger.info(f"Successfully updated public key for Snowflake user: {snowflake_username}")
                self.audit_logger.info(f"SNOWFLAKE_KEY_UPDATE|{snowflake_username}|{requesting_user or 'system'}|SUCCESS")
                
                return True
                
        except SnowflakeError:
            raise
        except Exception as e:
            error_msg = f"Failed to update public key for Snowflake user {snowflake_username}: {str(e)}"
            self.logger.error(error_msg)
            self.audit_logger.info(f"SNOWFLAKE_KEY_UPDATE|{snowflake_username}|{requesting_user or 'system'}|FAILED|{str(e)}")
            raise SnowflakeError(error_msg)
    
    def user_exists(self, snowflake_username: str) -> bool:
        """Check if a Snowflake user exists"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Query to check if user exists
                cursor.execute(f"SHOW USERS LIKE '{snowflake_username}'")
                users = cursor.fetchall()
                
                exists = len(users) > 0
                self.logger.debug(f"Snowflake user {snowflake_username} exists: {exists}")
                
                return exists
                
        except Exception as e:
            error_msg = f"Failed to check if Snowflake user {snowflake_username} exists: {str(e)}"
            self.logger.error(error_msg)
            raise SnowflakeError(error_msg)
    
    def get_user_info(self, snowflake_username: str) -> Optional[Dict[str, Any]]:
        """Get information about a Snowflake user"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Get user details
                cursor.execute(f"DESCRIBE USER {snowflake_username}")
                user_details = cursor.fetchall()
                
                # Convert to dictionary
                user_info = {}
                for row in user_details:
                    property_name = row[0]
                    property_value = row[1]
                    user_info[property_name] = property_value
                
                return user_info
                
        except Exception as e:
            self.logger.error(f"Failed to get user info for {snowflake_username}: {str(e)}")
            return None
    
    def list_users_with_rsa_keys(self) -> List[Dict[str, str]]:
        """List all Snowflake users that have RSA public keys configured"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Get all users
                cursor.execute("SHOW USERS")
                all_users = cursor.fetchall()
                
                users_with_keys = []
                
                for user_row in all_users:
                    username = user_row[0]  # First column is typically the username
                    
                    try:
                        # Check if user has RSA key
                        cursor.execute(f"DESCRIBE USER {username}")
                        user_details = cursor.fetchall()
                        
                        has_rsa_key = any(
                            row[0] == 'RSA_PUBLIC_KEY' and row[1] 
                            for row in user_details
                        )
                        
                        if has_rsa_key:
                            users_with_keys.append({
                                "username": username,
                                "has_rsa_key": True
                            })
                            
                    except Exception as e:
                        self.logger.warning(f"Failed to check RSA key for user {username}: {str(e)}")
                        continue
                
                self.logger.info(f"Found {len(users_with_keys)} Snowflake users with RSA keys")
                return users_with_keys
                
        except Exception as e:
            error_msg = f"Failed to list users with RSA keys: {str(e)}"
            self.logger.error(error_msg)
            raise SnowflakeError(error_msg)
    
    def remove_user_public_key(self, snowflake_username: str, requesting_user: str = None) -> bool:
        """Remove a user's public key (set to NULL)"""
        try:
            if not self.user_exists(snowflake_username):
                raise SnowflakeError(f"Snowflake user '{snowflake_username}' does not exist")
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Remove user's RSA public key
                alter_user_sql = f"ALTER USER {snowflake_username} UNSET RSA_PUBLIC_KEY"
                cursor.execute(alter_user_sql)
                
                self.logger.info(f"Successfully removed public key for Snowflake user: {snowflake_username}")
                self.audit_logger.info(f"SNOWFLAKE_KEY_REMOVED|{snowflake_username}|{requesting_user or 'system'}|SUCCESS")
                
                return True
                
        except SnowflakeError:
            raise
        except Exception as e:
            error_msg = f"Failed to remove public key for Snowflake user {snowflake_username}: {str(e)}"
            self.logger.error(error_msg)
            self.audit_logger.info(f"SNOWFLAKE_KEY_REMOVED|{snowflake_username}|{requesting_user or 'system'}|FAILED|{str(e)}")
            raise SnowflakeError(error_msg)
    
    def _clean_public_key(self, public_key: str) -> str:
        """Clean public key by removing headers, footers, and newlines"""
        try:
            # Remove PEM headers and footers
            lines = public_key.strip().split('\n')
            key_lines = []
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('-----'):
                    key_lines.append(line)
            
            # Join all key data without newlines
            cleaned_key = ''.join(key_lines)
            
            if not cleaned_key:
                raise SnowflakeError("Public key appears to be empty after cleaning")
            
            return cleaned_key
            
        except Exception as e:
            raise SnowflakeError(f"Failed to clean public key: {str(e)}")
    
    def test_key_authentication(self, snowflake_username: str, private_key_path: str) -> bool:
        """Test if key-pair authentication works for a user (for validation purposes)"""
        try:
            # This would be used for testing - in practice, private keys should never leave Key Vault
            # This is here for completeness but should be used carefully
            
            test_params = {
                'account': settings.SNOWFLAKE_ACCOUNT,
                'user': snowflake_username,
                'private_key_file': private_key_path,
                'warehouse': settings.SNOWFLAKE_WAREHOUSE,
                'database': settings.SNOWFLAKE_DATABASE,
                'schema': settings.SNOWFLAKE_SCHEMA
            }
            
            with snowflake.connector.connect(**test_params) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT CURRENT_USER()")
                current_user = cursor.fetchone()[0]
                
                success = current_user.upper() == snowflake_username.upper()
                self.logger.info(f"Key authentication test for {snowflake_username}: {'SUCCESS' if success else 'FAILED'}")
                
                return success
                
        except Exception as e:
            self.logger.error(f"Key authentication test failed for {snowflake_username}: {str(e)}")
            return False