import streamlit as st
import msal
from typing import Optional, Dict, Any
from config.settings import settings
from config.logging_config import get_app_logger, get_audit_logger
from utils.exceptions import AuthenticationError, AuthorizationError, ConfigurationError

logger = get_app_logger(__name__)
audit_logger = get_audit_logger()

class AzureADAuth:
    """Azure Active Directory authentication handler"""
    
    def __init__(self):
        self.client_id = settings.AZURE_AD_CLIENT_ID
        self.client_secret = settings.AZURE_AD_CLIENT_SECRET
        self.tenant_id = settings.AZURE_AD_TENANT_ID
        
        if not all([self.client_id, self.client_secret, self.tenant_id]):
            raise ConfigurationError("Azure AD configuration is incomplete")
        
        self.authority = f"https://login.microsoftonline.com/{self.tenant_id}"
        self.scope = ["User.Read", "Directory.Read.All"]
        
        # Initialize MSAL app
        self.app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=self.authority
        )
    
    def get_authorization_url(self) -> str:
        """Get the authorization URL for Azure AD login"""
        try:
            # Generate authorization URL
            auth_url = self.app.get_authorization_request_url(
                scopes=self.scope,
                redirect_uri=self._get_redirect_uri()
            )
            
            logger.info("Generated Azure AD authorization URL")
            return auth_url
            
        except Exception as e:
            logger.error(f"Failed to generate authorization URL: {str(e)}")
            raise AuthenticationError(f"Failed to generate login URL: {str(e)}")
    
    def authenticate_with_code(self, auth_code: str) -> Dict[str, Any]:
        """Exchange authorization code for access token and user info"""
        try:
            # Exchange code for token
            result = self.app.acquire_token_by_authorization_code(
                code=auth_code,
                scopes=self.scope,
                redirect_uri=self._get_redirect_uri()
            )
            
            if "error" in result:
                error_msg = f"Authentication failed: {result.get('error_description', result['error'])}"
                logger.error(error_msg)
                raise AuthenticationError(error_msg)
            
            # Get user information
            user_info = self._get_user_info(result["access_token"])
            
            # Log successful authentication
            audit_logger.info(f"USER_LOGIN|{user_info.get('userPrincipalName', 'unknown')}|SUCCESS")
            logger.info(f"User authenticated successfully: {user_info.get('userPrincipalName')}")
            
            return {
                "access_token": result["access_token"],
                "user_info": user_info
            }
            
        except AuthenticationError:
            raise
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            audit_logger.info(f"USER_LOGIN|unknown|FAILED|{str(e)}")
            raise AuthenticationError(f"Authentication failed: {str(e)}")
    
    def _get_user_info(self, access_token: str) -> Dict[str, Any]:
        """Get user information from Microsoft Graph API"""
        import requests
        
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(
                "https://graph.microsoft.com/v1.0/me",
                headers=headers
            )
            
            if response.status_code == 200:
                return response.json()
            else:
                raise AuthenticationError(f"Failed to get user info: {response.status_code}")
                
        except requests.RequestException as e:
            raise AuthenticationError(f"Failed to retrieve user information: {str(e)}")
    
    def _get_redirect_uri(self) -> str:
        """Get the redirect URI for the application"""
        # For Streamlit, we'll use a simple callback approach
        return "http://localhost:8501"

class RoleBasedAccessControl:
    """Role-based access control system"""
    
    # Define roles and their permissions
    ROLES = {
        "admin": {
            "permissions": ["create_key", "rotate_key", "delete_key", "view_all_keys", "manage_users"],
            "description": "Full access to all operations"
        },
        "key_manager": {
            "permissions": ["create_key", "rotate_key", "view_own_keys"],
            "description": "Can manage their own service account keys"
        },
        "viewer": {
            "permissions": ["view_own_keys"],
            "description": "Can only view their own service account keys"
        }
    }
    
    def __init__(self):
        self.logger = get_app_logger(__name__)
        self.audit_logger = get_audit_logger()
    
    def get_user_role(self, user_principal_name: str) -> str:
        """Get user role based on their principal name or group membership"""
        try:
            # For now, implement simple role assignment based on email domain/patterns
            # In production, this would query Azure AD groups or a role management system
            
            if user_principal_name.lower().endswith("@admin.company.com"):
                return "admin"
            elif "platform" in user_principal_name.lower() or "devops" in user_principal_name.lower():
                return "admin" 
            else:
                return "key_manager"  # Default role for TAOs
                
        except Exception as e:
            self.logger.error(f"Failed to determine user role for {user_principal_name}: {str(e)}")
            return "viewer"  # Most restrictive role as fallback
    
    def check_permission(self, user_role: str, permission: str) -> bool:
        """Check if a user role has a specific permission"""
        try:
            role_config = self.ROLES.get(user_role, {})
            permissions = role_config.get("permissions", [])
            return permission in permissions
            
        except Exception as e:
            self.logger.error(f"Failed to check permission {permission} for role {user_role}: {str(e)}")
            return False
    
    def enforce_permission(self, user_principal_name: str, permission: str):
        """Enforce permission check and raise exception if not authorized"""
        user_role = self.get_user_role(user_principal_name)
        
        if not self.check_permission(user_role, permission):
            error_msg = f"User {user_principal_name} (role: {user_role}) lacks permission: {permission}"
            self.logger.warning(error_msg)
            self.audit_logger.info(f"ACCESS_DENIED|{user_principal_name}|{permission}|{user_role}")
            raise AuthorizationError(error_msg)
        
        self.audit_logger.info(f"ACCESS_GRANTED|{user_principal_name}|{permission}|{user_role}")

def authenticate_user() -> bool:
    """Main authentication function for Streamlit app"""
    try:
        # Initialize session state
        if "authenticated" not in st.session_state:
            st.session_state.authenticated = False
            st.session_state.user_info = None
            st.session_state.access_token = None
        
        # If already authenticated, return True
        if st.session_state.authenticated:
            return True
        
        # Check if we're in development mode (skip auth for testing)
        if settings.is_development() and st.secrets.get("skip_auth", False):
            st.session_state.authenticated = True
            st.session_state.user_info = {
                "userPrincipalName": "dev@company.com",
                "displayName": "Development User"
            }
            return True
        
        # Show authentication UI
        st.sidebar.header("🔐 Authentication Required")
        st.sidebar.info("Please authenticate with Azure AD to access this application.")
        
        # Initialize Azure AD auth
        azure_auth = AzureADAuth()
        
        # Handle authentication flow
        if st.sidebar.button("Login with Azure AD"):
            auth_url = azure_auth.get_authorization_url()
            st.sidebar.markdown(f"[Click here to login]({auth_url})")
            st.sidebar.info("After logging in, you'll be redirected back to this application.")
        
        # Handle callback (in a real implementation, this would be handled differently)
        auth_code = st.sidebar.text_input("Enter authorization code (for development):", type="password")
        
        if auth_code:
            try:
                auth_result = azure_auth.authenticate_with_code(auth_code)
                st.session_state.authenticated = True
                st.session_state.user_info = auth_result["user_info"]
                st.session_state.access_token = auth_result["access_token"]
                st.rerun()
                
            except AuthenticationError as e:
                st.sidebar.error(f"Authentication failed: {str(e)}")
        
        return False
        
    except Exception as e:
        logger = get_app_logger(__name__)
        logger.error(f"Authentication error: {str(e)}")
        st.sidebar.error("Authentication system error. Please contact support.")
        return False

def get_current_user() -> Optional[Dict[str, Any]]:
    """Get current authenticated user information"""
    return st.session_state.get("user_info")

def get_current_user_role() -> str:
    """Get current user's role"""
    user_info = get_current_user()
    if not user_info:
        return "viewer"
    
    rbac = RoleBasedAccessControl()
    return rbac.get_user_role(user_info.get("userPrincipalName", ""))

def require_permission(permission: str):
    """Decorator to require specific permission for a function"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            user_info = get_current_user()
            if not user_info:
                raise AuthenticationError("User not authenticated")
            
            rbac = RoleBasedAccessControl()
            rbac.enforce_permission(user_info["userPrincipalName"], permission)
            
            return func(*args, **kwargs)
        return wrapper
    return decorator