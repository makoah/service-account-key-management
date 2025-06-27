import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any
import plotly.express as px
import plotly.graph_objects as go
from utils.keyvault_client import KeyVaultClient
from utils.snowflake_client import SnowflakeClient
from utils.crypto_utils import generate_key_pair
from utils.auth import authenticate_user, get_current_user, get_current_user_role, require_permission
from utils.audit_logger import sox_audit_logger
from utils.exceptions import KeyVaultError, SnowflakeError, AuthenticationError
from config.logging_config import setup_logging, get_app_logger

# Initialize logging
setup_logging()
logger = get_app_logger(__name__)

st.set_page_config(
    page_title="Service Account Key Management",
    page_icon="🔐", 
    layout="wide"
)

def main():
    st.title("🔐 Service Account Key-Pair Management")
    
    # Authentication
    if not authenticate_user():
        st.error("Access denied. Please contact your administrator.")
        return
    
    # Get current user info
    current_user = get_current_user()
    user_role = get_current_user_role()
    
    # Display user info in sidebar
    st.sidebar.markdown("---")
    st.sidebar.markdown(f"**Logged in as:** {current_user.get('displayName', 'Unknown')}")
    st.sidebar.markdown(f"**Role:** {user_role.title()}")
    st.sidebar.markdown(f"**Email:** {current_user.get('userPrincipalName', 'Unknown')}")
    st.sidebar.markdown("---")
    
    # Initialize clients with error handling
    try:
        kv_client = KeyVaultClient()
        sf_client = SnowflakeClient()
    except Exception as e:
        st.error(f"Failed to initialize services: {str(e)}")
        logger.error(f"Service initialization failed: {str(e)}")
        return
    
    # Sidebar navigation
    page = st.sidebar.selectbox(
        "Navigation",
        ["Dashboard", "Generate Key-Pair", "Manage Keys", "Usage Tracking"]
    )
    
    if page == "Dashboard":
        show_dashboard(kv_client, sf_client, current_user, user_role)
    elif page == "Generate Key-Pair":
        show_generate_keys(kv_client, sf_client, current_user, user_role)
    elif page == "Manage Keys":
        show_manage_keys(kv_client, sf_client, current_user, user_role)
    elif page == "Usage Tracking":
        show_usage_tracking(kv_client, current_user, user_role)

def show_dashboard(kv_client: KeyVaultClient, sf_client: SnowflakeClient, current_user: Dict, user_role: str):
    """Main dashboard showing service account overview and metrics"""
    st.header("📊 Dashboard")
    
    try:
        # Get user's keys (filtered by user for non-admins)
        user_principal_name = current_user.get('userPrincipalName')
        
        if user_role == "admin":
            all_keys = kv_client.list_keys()
            user_keys = kv_client.list_keys(user_filter=user_principal_name)
        else:
            all_keys = kv_client.list_keys(user_filter=user_principal_name)
            user_keys = all_keys
        
        # Metrics row
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric(
                "Your Key Pairs", 
                len(user_keys),
                help="Number of service account key pairs you own"
            )
        
        with col2:
            if user_role == "admin":
                st.metric(
                    "Total Key Pairs", 
                    len(all_keys),
                    help="Total key pairs in the system"
                )
            else:
                # Get Snowflake users with keys
                try:
                    sf_users = sf_client.list_users_with_rsa_keys()
                    st.metric(
                        "Snowflake Users", 
                        len(sf_users),
                        help="Snowflake users with RSA keys configured"
                    )
                except Exception as e:
                    st.metric("Snowflake Users", "Error", help="Unable to connect to Snowflake")
        
        with col3:
            # Calculate recent activity (last 7 days)
            recent_count = _count_recent_activity(kv_client, user_keys, days=7)
            st.metric(
                "Recent Activity", 
                recent_count,
                help="Key operations in the last 7 days"
            )
        
        with col4:
            st.metric(
                "Your Role", 
                user_role.title(),
                help="Your access level in the system"
            )
        
        # Dashboard content in tabs
        tab1, tab2, tab3 = st.tabs(["📋 Your Service Accounts", "📈 Activity Overview", "🔍 Quick Actions"])
        
        with tab1:
            _show_service_accounts_overview(kv_client, user_keys, user_principal_name)
        
        with tab2:
            _show_activity_overview(kv_client, sf_client, user_keys, user_role)
        
        with tab3:
            _show_quick_actions(kv_client, sf_client, current_user, user_role)
    
    except Exception as e:
        st.error(f"Error loading dashboard: {str(e)}")
        logger.error(f"Dashboard error for user {user_principal_name}: {str(e)}")

def _show_service_accounts_overview(kv_client: KeyVaultClient, user_keys: List[str], user_principal_name: str):
    """Show overview of user's service accounts"""
    if not user_keys:
        st.info("You don't have any service account key pairs yet. Use the 'Generate Key-Pair' page to create your first one.")
        return
    
    # Create dataframe of service accounts
    accounts_data = []
    for service_account in user_keys:
        try:
            metadata = kv_client.get_key_metadata(service_account)
            accounts_data.append({
                "Service Account": service_account,
                "Snowflake User": metadata.get("snowflake_user", "N/A"),
                "Usage Type": metadata.get("usage_type", "N/A"),
                "Created": metadata.get("created_at", "Unknown")[:10] if metadata.get("created_at") else "Unknown",
                "Description": metadata.get("description", "No description")[:50] + "..." if len(metadata.get("description", "")) > 50 else metadata.get("description", "No description")
            })
        except Exception as e:
            logger.warning(f"Failed to get metadata for {service_account}: {str(e)}")
            accounts_data.append({
                "Service Account": service_account,
                "Snowflake User": "Error",
                "Usage Type": "Error",
                "Created": "Unknown",
                "Description": "Unable to load metadata"
            })
    
    if accounts_data:
        df = pd.DataFrame(accounts_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # Quick stats
        col1, col2 = st.columns(2)
        with col1:
            usage_counts = df['Usage Type'].value_counts()
            if len(usage_counts) > 0:
                fig = px.pie(
                    values=usage_counts.values, 
                    names=usage_counts.index,
                    title="Key Pairs by Usage Type"
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Recent vs older keys
            current_year = datetime.now().year
            recent_keys = len([acc for acc in accounts_data if acc["Created"] != "Unknown" and acc["Created"].startswith(str(current_year))])
            older_keys = len(accounts_data) - recent_keys
            
            if recent_keys > 0 or older_keys > 0:
                fig = go.Figure(data=[
                    go.Bar(name='This Year', x=['Key Pairs'], y=[recent_keys]),
                    go.Bar(name='Previous Years', x=['Key Pairs'], y=[older_keys])
                ])
                fig.update_layout(title="Keys by Creation Year")
                st.plotly_chart(fig, use_container_width=True)

def _show_activity_overview(kv_client: KeyVaultClient, sf_client: SnowflakeClient, user_keys: List[str], user_role: str):
    """Show activity overview and recent operations"""
    st.subheader("Recent Activity")
    
    try:
        # Get recent activity from Key Vault
        recent_activity = kv_client.get_recent_activity()
        
        if recent_activity:
            # Filter activity for non-admin users
            if user_role != "admin":
                recent_activity = [
                    activity for activity in recent_activity 
                    if activity.get("Service Account") in user_keys
                ]
            
            if recent_activity:
                activity_df = pd.DataFrame(recent_activity)
                st.dataframe(activity_df, use_container_width=True, hide_index=True)
                
                # Activity timeline
                if len(recent_activity) > 1:
                    # Create timeline chart
                    dates = [datetime.fromisoformat(act.get("Date", "2024-01-01").replace("Z", "")) if act.get("Date") != "Unknown" else datetime.now() for act in recent_activity]
                    actions = [act.get("Action", "Unknown") for act in recent_activity]
                    
                    timeline_df = pd.DataFrame({
                        "Date": dates,
                        "Action": actions,
                        "Count": [1] * len(dates)
                    })
                    
                    # Group by date and action
                    timeline_summary = timeline_df.groupby([timeline_df["Date"].dt.date, "Action"]).sum().reset_index()
                    
                    if not timeline_summary.empty:
                        fig = px.line(
                            timeline_summary, 
                            x="Date", 
                            y="Count", 
                            color="Action",
                            title="Activity Timeline"
                        )
                        st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No recent activity for your service accounts.")
        else:
            st.info("No recent activity data available.")
    
    except Exception as e:
        st.error(f"Error loading activity data: {str(e)}")
        logger.error(f"Activity overview error: {str(e)}")

def _show_quick_actions(kv_client: KeyVaultClient, sf_client: SnowflakeClient, current_user: Dict, user_role: str):
    """Show quick action buttons and shortcuts"""
    st.subheader("Quick Actions")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("🔑 Generate New Key Pair", use_container_width=True):
            st.info("Navigate to 'Generate Key-Pair' page using the sidebar menu.")
    
    with col2:
        if st.button("🔧 Manage Existing Keys", use_container_width=True):
            st.info("Navigate to 'Manage Keys' page using the sidebar menu.")
    
    with col3:
        if st.button("📊 View Usage Tracking", use_container_width=True):
            st.info("Navigate to 'Usage Tracking' page using the sidebar menu.")
    
    # System status
    st.subheader("System Status")
    
    status_col1, status_col2 = st.columns(2)
    
    with status_col1:
        # Test Key Vault connection
        try:
            kv_client.list_keys()[:1]  # Quick test
            st.success("✅ Azure Key Vault: Connected")
        except Exception as e:
            st.error(f"❌ Azure Key Vault: {str(e)[:50]}...")
    
    with status_col2:
        # Test Snowflake connection
        try:
            sf_client.list_users_with_rsa_keys()[:1]  # Quick test
            st.success("✅ Snowflake: Connected")
        except Exception as e:
            st.error(f"❌ Snowflake: {str(e)[:50]}...")
    
    # Recent system metrics
    if user_role == "admin":
        st.subheader("System Metrics (Admin)")
        
        try:
            all_keys = kv_client.list_keys()
            
            metrics_col1, metrics_col2, metrics_col3 = st.columns(3)
            
            with metrics_col1:
                st.metric("Total Service Accounts", len(all_keys))
            
            with metrics_col2:
                # Count unique users
                unique_users = set()
                for key in all_keys[:10]:  # Sample to avoid performance issues
                    try:
                        metadata = kv_client.get_key_metadata(key)
                        if metadata.get("created_by"):
                            unique_users.add(metadata["created_by"])
                    except:
                        pass
                st.metric("Active Users", len(unique_users))
            
            with metrics_col3:
                recent_count = _count_recent_activity(kv_client, all_keys, days=30)
                st.metric("Activity (30 days)", recent_count)
        
        except Exception as e:
            st.error(f"Error loading admin metrics: {str(e)}")

def _count_recent_activity(kv_client: KeyVaultClient, keys: List[str], days: int = 7) -> int:
    """Count recent activity for given keys"""
    try:
        cutoff_date = datetime.now() - timedelta(days=days)
        recent_count = 0
        
        for key in keys:
            try:
                metadata = kv_client.get_key_metadata(key)
                created_at = metadata.get("created_at")
                if created_at:
                    created_date = datetime.fromisoformat(created_at.replace("Z", ""))
                    if created_date > cutoff_date:
                        recent_count += 1
            except:
                continue
        
        return recent_count
    except:
        return 0

def show_generate_keys(kv_client: KeyVaultClient, sf_client: SnowflakeClient, current_user: Dict, user_role: str):
    """Key generation form with comprehensive validation"""
    st.header("🔑 Generate New Key-Pair")
    
    # Check permissions
    try:
        from utils.auth import RoleBasedAccessControl
        rbac = RoleBasedAccessControl()
        rbac.enforce_permission(current_user.get('userPrincipalName'), 'create_key')
    except Exception as e:
        st.error(f"Access denied: {str(e)}")
        return
    
    st.markdown("""
    This form will generate a new RSA key pair for your service account and automatically:
    - Store the private key securely in Azure Key Vault
    - Update the Snowflake user with the public key
    - Create audit logs for compliance tracking
    """)
    
    # Pre-flight checks
    with st.expander("🔍 System Status Check", expanded=False):
        col1, col2 = st.columns(2)
        
        kv_status = _check_keyvault_status(kv_client)
        sf_status = _check_snowflake_status(sf_client)
        
        with col1:
            if kv_status:
                st.success("✅ Azure Key Vault: Ready")
            else:
                st.error("❌ Azure Key Vault: Not accessible")
        
        with col2:
            if sf_status:
                st.success("✅ Snowflake: Ready")  
            else:
                st.error("❌ Snowflake: Not accessible")
        
        if not (kv_status and sf_status):
            st.warning("⚠️ Some services are not available. Key generation may fail.")
    
    # Main form
    with st.form("generate_keys_form", clear_on_submit=False):
        st.subheader("Key Pair Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            service_account = st.text_input(
                "Service Account Name *",
                help="Unique identifier for this service account (alphanumeric, hyphens, underscores only)",
                placeholder="e.g., powerbi-sales-dashboard"
            )
            
            snowflake_user = st.text_input(
                "Snowflake Username *",
                help="Existing Snowflake user that will use this key pair",
                placeholder="e.g., SVC_POWERBI_USER"
            )
            
            usage_type = st.selectbox(
                "Usage Type *",
                ["PowerBI", "Tableau", "Python Scripts", "Power Apps", "Other"],
                help="Primary application that will use this key pair"
            )
        
        with col2:
            key_size = st.selectbox(
                "RSA Key Size",
                [2048, 3072, 4096],
                index=0,
                help="Larger keys are more secure but may impact performance"
            )
            
            description = st.text_area(
                "Description",
                help="Optional description of the service account purpose",
                placeholder="e.g., Used by PowerBI for sales dashboard data access"
            )
            
            # Advanced options
            with st.expander("Advanced Options"):
                verify_snowflake_user = st.checkbox(
                    "Verify Snowflake user exists",
                    value=True,
                    help="Check if the Snowflake user exists before generating keys"
                )
                
                test_key_after_generation = st.checkbox(
                    "Test key after generation",
                    value=False,
                    help="Perform a test connection to verify the key works (optional)"
                )
        
        # Form validation
        submitted = st.form_submit_button("🔑 Generate Key-Pair", use_container_width=True)
        
        if submitted:
            # Validate inputs
            validation_errors = _validate_key_generation_form(
                service_account, snowflake_user, usage_type, kv_client, sf_client, verify_snowflake_user
            )
            
            if validation_errors:
                for error in validation_errors:
                    st.error(error)
            else:
                # Generate the key pair
                _process_key_generation(
                    kv_client, sf_client, current_user,
                    service_account, snowflake_user, usage_type, description,
                    key_size, test_key_after_generation
                )
    
    # Show existing keys for reference
    st.markdown("---")
    st.subheader("📋 Your Existing Service Accounts")
    
    try:
        user_keys = kv_client.list_keys(user_filter=current_user.get('userPrincipalName'))
        if user_keys:
            # Create simple table
            existing_data = []
            for key in user_keys:
                try:
                    metadata = kv_client.get_key_metadata(key)
                    existing_data.append({
                        "Service Account": key,
                        "Snowflake User": metadata.get("snowflake_user", "N/A"),
                        "Usage Type": metadata.get("usage_type", "N/A"),
                        "Created": metadata.get("created_at", "Unknown")[:10] if metadata.get("created_at") else "Unknown"
                    })
                except:
                    existing_data.append({
                        "Service Account": key,
                        "Snowflake User": "Error loading",
                        "Usage Type": "Error loading", 
                        "Created": "Unknown"
                    })
            
            if existing_data:
                df = pd.DataFrame(existing_data)
                st.dataframe(df, use_container_width=True, hide_index=True)
        else:
            st.info("You don't have any existing service account key pairs.")
    
    except Exception as e:
        st.warning(f"Could not load existing keys: {str(e)}")

def _validate_key_generation_form(service_account: str, snowflake_user: str, usage_type: str, 
                                  kv_client: KeyVaultClient, sf_client: SnowflakeClient, 
                                  verify_snowflake_user: bool) -> List[str]:
    """Validate the key generation form inputs"""
    errors = []
    
    # Service account name validation
    if not service_account:
        errors.append("Service Account Name is required")
    elif not _validate_service_account_name(service_account):
        errors.append("Service Account Name must contain only alphanumeric characters, hyphens, and underscores")
    elif len(service_account) < 3:
        errors.append("Service Account Name must be at least 3 characters long")
    elif len(service_account) > 50:
        errors.append("Service Account Name must be 50 characters or less")
    else:
        # Check if service account already exists
        try:
            existing_keys = kv_client.list_keys()
            if service_account in existing_keys:
                errors.append(f"Service Account '{service_account}' already exists. Choose a different name.")
        except Exception as e:
            errors.append(f"Could not verify service account uniqueness: {str(e)}")
    
    # Snowflake username validation
    if not snowflake_user:
        errors.append("Snowflake Username is required")
    elif not _validate_snowflake_username(snowflake_user):
        errors.append("Snowflake Username contains invalid characters")
    elif verify_snowflake_user:
        try:
            if not sf_client.user_exists(snowflake_user):
                errors.append(f"Snowflake user '{snowflake_user}' does not exist")
        except Exception as e:
            errors.append(f"Could not verify Snowflake user: {str(e)}")
    
    # Usage type validation
    if not usage_type:
        errors.append("Usage Type is required")
    
    return errors

def _validate_service_account_name(name: str) -> bool:
    """Validate service account name format"""
    import re
    return bool(re.match(r'^[a-zA-Z0-9_-]+$', name))

def _validate_snowflake_username(username: str) -> bool:
    """Validate Snowflake username format"""
    import re
    # Snowflake usernames are more permissive but let's be conservative
    return bool(re.match(r'^[a-zA-Z0-9_]+$', username))

def _check_keyvault_status(kv_client: KeyVaultClient) -> bool:
    """Check if Key Vault is accessible"""
    try:
        kv_client.list_keys()[:1]
        return True
    except:
        return False

def _check_snowflake_status(sf_client: SnowflakeClient) -> bool:
    """Check if Snowflake is accessible"""
    try:
        sf_client.list_users_with_rsa_keys()[:1]
        return True
    except:
        return False

def _process_key_generation(kv_client: KeyVaultClient, sf_client: SnowflakeClient, current_user: Dict,
                           service_account: str, snowflake_user: str, usage_type: str, description: str,
                           key_size: int, test_key: bool):
    """Process the key generation request"""
    
    user_principal_name = current_user.get('userPrincipalName')
    progress_bar = st.progress(0, "Starting key generation...")
    
    try:
        # Step 1: Generate RSA key pair
        progress_bar.progress(20, "Generating RSA key pair...")
        private_key, public_key = generate_key_pair(key_size, user_principal_name)
        
        # Step 2: Store in Key Vault
        progress_bar.progress(40, "Storing keys in Azure Key Vault...")
        metadata = {
            "snowflake_user": snowflake_user,
            "usage_type": usage_type,
            "description": description,
            "key_size": key_size,
            "created_at": datetime.now().isoformat()
        }
        
        kv_client.store_key_pair(
            service_account,
            private_key,
            public_key,
            metadata,
            user_principal_name
        )
        
        # Step 3: Update Snowflake user
        progress_bar.progress(60, "Updating Snowflake user...")
        sf_client.update_user_public_key(snowflake_user, public_key, user_principal_name)
        
        # Step 4: Optional testing
        if test_key:
            progress_bar.progress(80, "Testing key authentication...")
            # Note: In production, we wouldn't test with the actual private key
            # This is just a placeholder for the testing logic
            st.info("Key testing is not implemented in this demo version for security reasons.")
        
        # Step 5: Complete
        progress_bar.progress(100, "Key generation complete!")
        
        # Success message with details
        st.success("🎉 Key-pair generated successfully!")
        
        # Show summary
        with st.expander("📋 Generation Summary", expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"""
                **Service Account:** {service_account}  
                **Snowflake User:** {snowflake_user}  
                **Usage Type:** {usage_type}  
                **Key Size:** {key_size} bits  
                """)
            
            with col2:
                st.markdown(f"""
                **Created By:** {current_user.get('displayName', 'Unknown')}  
                **Created At:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
                **Status:** ✅ Active  
                **Location:** Azure Key Vault  
                """)
            
            if description:
                st.markdown(f"**Description:** {description}")
        
        # Next steps
        st.info("""
        **Next Steps:**
        1. Your service account can now authenticate to Snowflake using key-pair authentication
        2. Use the 'Manage Keys' page to download the public key if needed for other systems
        3. The private key is securely stored in Azure Key Vault and should never be downloaded
        """)
        
        # Log the successful operation
        sox_audit_logger.log_key_operation(
            "GENERATED",
            service_account,
            user_principal_name,
            True,
            key_size=key_size
        )
        
    except Exception as e:
        error_msg = str(e)
        st.error(f"❌ Key generation failed: {error_msg}")
        logger.error(f"Key generation failed for {service_account}: {error_msg}")
        
        # Log the failed operation
        sox_audit_logger.log_key_operation(
            "GENERATED",
            service_account,
            user_principal_name,
            False,
            error_message=error_msg
        )
        
        # Clean up any partial state
        try:
            # If Key Vault storage succeeded but Snowflake update failed, 
            # we might want to clean up (depending on business logic)
            pass
        except:
            pass
    
    finally:
        # Clear the progress bar
        progress_bar.empty()

def show_manage_keys(kv_client, sf_client):
    st.header("Manage Existing Keys")
    
    keys = kv_client.list_keys()
    
    if not keys:
        st.info("No key pairs found")
        return
    
    # Display keys in a table
    key_data = []
    for key in keys:
        metadata = kv_client.get_key_metadata(key)
        key_data.append({
            "Service Account": key,
            "Snowflake User": metadata.get("snowflake_user", "N/A"),
            "Usage Type": metadata.get("usage_type", "N/A"),
            "Created": metadata.get("created_at", "N/A")
        })
    
    df = pd.DataFrame(key_data)
    st.dataframe(df, use_container_width=True)
    
    # Key management actions
    st.subheader("Key Actions")
    selected_key = st.selectbox("Select Key to Manage", keys)
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Rotate Key"):
            rotate_key(kv_client, sf_client, selected_key)
    
    with col2:
        if st.button("Download Public Key"):
            download_public_key(kv_client, selected_key)
    
    with col3:
        if st.button("Delete Key", type="secondary"):
            delete_key(kv_client, sf_client, selected_key)

def show_usage_tracking():
    st.header("Usage Tracking")
    
    # Service usage metrics
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("PowerBI Usage")
        # Mock data - replace with actual PowerBI API calls
        powerbi_data = pd.DataFrame({
            "Date": pd.date_range("2024-01-01", periods=30),
            "Connections": [10, 15, 12, 8, 20, 25, 18, 14, 16, 22] * 3
        })
        st.line_chart(powerbi_data.set_index("Date"))
    
    with col2:
        st.subheader("Tableau Usage") 
        # Mock data - replace with actual Tableau API calls
        tableau_data = pd.DataFrame({
            "Date": pd.date_range("2024-01-01", periods=30),
            "Connections": [8, 12, 10, 15, 18, 20, 16, 12, 14, 19] * 3
        })
        st.line_chart(tableau_data.set_index("Date"))

def rotate_key(kv_client, sf_client, service_account):
    try:
        with st.spinner("Rotating key..."):
            # Generate new key pair
            private_key, public_key = generate_key_pair()
            
            # Get existing metadata
            metadata = kv_client.get_key_metadata(service_account)
            snowflake_user = metadata.get("snowflake_user")
            
            # Update Key Vault
            kv_client.store_key_pair(service_account, private_key, public_key, metadata)
            
            # Update Snowflake
            if snowflake_user:
                sf_client.update_user_public_key(snowflake_user, public_key)
            
            st.success(f"Key rotated successfully for {service_account}")
    except Exception as e:
        st.error(f"Error rotating key: {str(e)}")

def download_public_key(kv_client, service_account):
    try:
        public_key = kv_client.get_public_key(service_account)
        st.download_button(
            label="Download Public Key",
            data=public_key,
            file_name=f"{service_account}_public_key.pem",
            mime="text/plain"
        )
    except Exception as e:
        st.error(f"Error downloading key: {str(e)}")

def delete_key(kv_client, sf_client, service_account):
    if st.checkbox(f"I confirm deletion of {service_account}"):
        try:
            with st.spinner("Deleting key..."):
                kv_client.delete_key(service_account)
                st.success(f"Key deleted for {service_account}")
        except Exception as e:
            st.error(f"Error deleting key: {str(e)}")

if __name__ == "__main__":
    main()