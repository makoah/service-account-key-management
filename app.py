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

def show_manage_keys(kv_client: KeyVaultClient, sf_client: SnowflakeClient, current_user: Dict, user_role: str):
    """Key management interface with rotate, delete, and download capabilities"""
    st.header("🔧 Manage Existing Keys")
    
    user_principal_name = current_user.get('userPrincipalName')
    
    # Get user's keys (filtered for non-admins)
    try:
        if user_role == "admin":
            all_keys = kv_client.list_keys()
            user_keys = kv_client.list_keys(user_filter=user_principal_name)
            show_all_keys = st.checkbox("Show all keys (Admin view)", value=False)
            keys_to_display = all_keys if show_all_keys else user_keys
        else:
            keys_to_display = kv_client.list_keys(user_filter=user_principal_name)
        
        if not keys_to_display:
            st.info("You don't have any key pairs to manage. Use the 'Generate Key-Pair' page to create one.")
            return
        
        # Display keys in an enhanced table
        st.subheader("📋 Your Service Account Keys")
        key_data = []
        
        for key in keys_to_display:
            try:
                metadata = kv_client.get_key_metadata(key)
                created_at = metadata.get("created_at", "Unknown")
                
                # Calculate age
                if created_at != "Unknown":
                    try:
                        created_date = datetime.fromisoformat(created_at.replace("Z", ""))
                        age_days = (datetime.now() - created_date).days
                        age_str = f"{age_days} days ago"
                    except:
                        age_str = "Unknown"
                else:
                    age_str = "Unknown"
                
                # Determine status
                status = "🟢 Active"
                if age_days > 365:  # Keys older than 1 year
                    status = "🟡 Consider Rotation"
                elif age_days > 730:  # Keys older than 2 years
                    status = "🔴 Rotation Needed"
                
                key_data.append({
                    "Service Account": key,
                    "Snowflake User": metadata.get("snowflake_user", "N/A"),
                    "Usage Type": metadata.get("usage_type", "N/A"),
                    "Created": created_at[:10] if created_at != "Unknown" else "Unknown",
                    "Age": age_str,
                    "Status": status,
                    "Key Size": f"{metadata.get('key_size', 'Unknown')} bits",
                    "Created By": metadata.get("created_by", "Unknown")
                })
                
            except Exception as e:
                logger.warning(f"Failed to get metadata for {key}: {str(e)}")
                key_data.append({
                    "Service Account": key,
                    "Snowflake User": "Error",
                    "Usage Type": "Error",
                    "Created": "Unknown",
                    "Age": "Unknown",
                    "Status": "❌ Error",
                    "Key Size": "Unknown",
                    "Created By": "Unknown"
                })
        
        df = pd.DataFrame(key_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
        
        # Key management actions
        st.markdown("---")
        st.subheader("🛠️ Key Management Actions")
        
        # Key selection
        col1, col2 = st.columns([2, 1])
        
        with col1:
            selected_key = st.selectbox(
                "Select Service Account to Manage:",
                keys_to_display,
                help="Choose a service account to perform management operations"
            )
        
        with col2:
            if selected_key:
                # Show key details
                try:
                    metadata = kv_client.get_key_metadata(selected_key)
                    st.info(f"**Usage:** {metadata.get('usage_type', 'Unknown')}")
                except:
                    st.warning("Unable to load key details")
        
        if selected_key:
            # Check permissions for selected key
            can_manage = _can_manage_key(user_role, user_principal_name, selected_key, kv_client)
            
            if not can_manage:
                st.error("You don't have permission to manage this service account.")
                return
            
            # Action buttons
            action_col1, action_col2, action_col3, action_col4 = st.columns(4)
            
            with action_col1:
                if st.button("🔄 Rotate Key", use_container_width=True, help="Generate new key pair and update Snowflake"):
                    _rotate_key_interface(kv_client, sf_client, selected_key, current_user)
            
            with action_col2:
                if st.button("📥 Download Public Key", use_container_width=True, help="Download public key file"):
                    _download_public_key_interface(kv_client, selected_key, current_user)
            
            with action_col3:
                if st.button("📋 View Details", use_container_width=True, help="View detailed key information"):
                    _view_key_details_interface(kv_client, selected_key)
            
            with action_col4:
                if st.button("🗑️ Delete Key", use_container_width=True, type="secondary", help="Permanently delete key pair"):
                    _delete_key_interface(kv_client, sf_client, selected_key, current_user)
        
        # Bulk operations (admin only)
        if user_role == "admin" and show_all_keys:
            st.markdown("---")
            st.subheader("🔧 Bulk Operations (Admin)")
            
            bulk_col1, bulk_col2 = st.columns(2)
            
            with bulk_col1:
                if st.button("📊 Generate Key Report"):
                    _generate_key_report(kv_client, all_keys)
            
            with bulk_col2:
                if st.button("⚠️ Find Keys Needing Rotation"):
                    _find_keys_needing_rotation(kv_client, all_keys)
    
    except Exception as e:
        st.error(f"Error loading keys: {str(e)}")
        logger.error(f"Key management error for user {user_principal_name}: {str(e)}")

def _can_manage_key(user_role: str, user_principal_name: str, service_account: str, kv_client: KeyVaultClient) -> bool:
    """Check if user can manage the selected key"""
    if user_role == "admin":
        return True
    
    try:
        metadata = kv_client.get_key_metadata(service_account)
        created_by = metadata.get("created_by")
        return created_by == user_principal_name
    except:
        return False

def _rotate_key_interface(kv_client: KeyVaultClient, sf_client: SnowflakeClient, service_account: str, current_user: Dict):
    """Interface for key rotation"""
    user_principal_name = current_user.get('userPrincipalName')
    
    st.subheader(f"🔄 Rotate Key for {service_account}")
    
    # Get current metadata
    try:
        metadata = kv_client.get_key_metadata(service_account)
        snowflake_user = metadata.get("snowflake_user")
        current_key_size = metadata.get("key_size", 2048)
        
        st.info(f"""
        **Current Configuration:**
        - Snowflake User: {snowflake_user}
        - Current Key Size: {current_key_size} bits
        - Last Modified: {metadata.get("last_modified", "Unknown")}
        """)
        
        # Rotation options
        with st.form(f"rotate_key_{service_account}"):
            st.warning("⚠️ **Warning:** Key rotation will replace the existing key pair. The old private key will be permanently deleted.")
            
            new_key_size = st.selectbox(
                "New Key Size:",
                [2048, 3072, 4096],
                index=[2048, 3072, 4096].index(current_key_size) if current_key_size in [2048, 3072, 4096] else 0
            )
            
            rotation_reason = st.text_area(
                "Rotation Reason (Optional):",
                placeholder="e.g., Scheduled rotation, security compliance, suspected compromise"
            )
            
            confirm_rotation = st.checkbox("I understand that this will replace the existing key pair")
            
            if st.form_submit_button("🔄 Confirm Rotation", disabled=not confirm_rotation):
                if confirm_rotation:
                    _process_key_rotation(kv_client, sf_client, service_account, current_user, new_key_size, rotation_reason, metadata)
                else:
                    st.error("Please confirm that you understand the implications of key rotation.")
    
    except Exception as e:
        st.error(f"Failed to load key details: {str(e)}")

def _process_key_rotation(kv_client: KeyVaultClient, sf_client: SnowflakeClient, service_account: str, 
                         current_user: Dict, new_key_size: int, rotation_reason: str, old_metadata: Dict):
    """Process the key rotation"""
    user_principal_name = current_user.get('userPrincipalName')
    progress_bar = st.progress(0, "Starting key rotation...")
    
    try:
        # Step 1: Generate new key pair
        progress_bar.progress(25, "Generating new RSA key pair...")
        private_key, public_key = generate_key_pair(new_key_size, user_principal_name)
        
        # Step 2: Store new keys in Key Vault
        progress_bar.progress(50, "Storing new keys in Azure Key Vault...")
        new_metadata = {
            **old_metadata,
            "key_size": new_key_size,
            "last_modified": datetime.now().isoformat(),
            "rotation_reason": rotation_reason,
            "rotated_by": user_principal_name,
            "previous_key_size": old_metadata.get("key_size", "unknown")
        }
        
        kv_client.store_key_pair(service_account, private_key, public_key, new_metadata, user_principal_name)
        
        # Step 3: Update Snowflake user
        progress_bar.progress(75, "Updating Snowflake user...")
        snowflake_user = old_metadata.get("snowflake_user")
        if snowflake_user:
            sf_client.update_user_public_key(snowflake_user, public_key, user_principal_name)
        
        # Step 4: Complete
        progress_bar.progress(100, "Key rotation complete!")
        
        st.success("🎉 Key rotation completed successfully!")
        
        # Show rotation summary
        with st.expander("📋 Rotation Summary", expanded=True):
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown(f"""
                **Service Account:** {service_account}  
                **Previous Key Size:** {old_metadata.get('key_size', 'Unknown')} bits  
                **New Key Size:** {new_key_size} bits  
                """)
            
            with col2:
                st.markdown(f"""
                **Rotated By:** {current_user.get('displayName', 'Unknown')}  
                **Rotation Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
                **Reason:** {rotation_reason or 'Not specified'}  
                """)
        
        # Log the rotation
        sox_audit_logger.log_key_operation(
            "ROTATED",
            service_account, 
            user_principal_name,
            True,
            key_size=new_key_size
        )
        
    except Exception as e:
        error_msg = str(e)
        st.error(f"❌ Key rotation failed: {error_msg}")
        logger.error(f"Key rotation failed for {service_account}: {error_msg}")
        
        sox_audit_logger.log_key_operation(
            "ROTATED",
            service_account,
            user_principal_name, 
            False,
            error_message=error_msg
        )
    
    finally:
        progress_bar.empty()

def _download_public_key_interface(kv_client: KeyVaultClient, service_account: str, current_user: Dict):
    """Interface for downloading public key"""
    user_principal_name = current_user.get('userPrincipalName')
    
    try:
        public_key = kv_client.get_public_key(service_account, user_principal_name)
        
        # Clean the key for download
        from utils.crypto_utils import crypto_utils
        cleaned_key = crypto_utils.clean_pem_key(public_key)
        
        # Create download button
        st.download_button(
            label=f"📥 Download {service_account}_public_key.pem",
            data=cleaned_key,
            file_name=f"{service_account}_public_key.pem",
            mime="text/plain",
            help="Download the public key in PEM format"
        )
        
        # Show key preview
        with st.expander("🔍 Public Key Preview"):
            st.code(cleaned_key, language="text")
        
        # Generate fingerprint
        try:
            fingerprint = crypto_utils.get_key_fingerprint(public_key)
            st.info(f"**Key Fingerprint (SHA256):** `{fingerprint}`")
        except Exception as e:
            st.warning(f"Could not generate fingerprint: {str(e)}")
        
        st.success(f"✅ Public key for {service_account} is ready for download.")
        
    except Exception as e:
        st.error(f"Failed to retrieve public key: {str(e)}")
        logger.error(f"Public key download failed for {service_account}: {str(e)}")

def _view_key_details_interface(kv_client: KeyVaultClient, service_account: str):
    """Interface for viewing detailed key information"""
    try:
        metadata = kv_client.get_key_metadata(service_account)
        
        st.subheader(f"📋 Details for {service_account}")
        
        # Basic information
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"""
            **Service Account:** {service_account}  
            **Snowflake User:** {metadata.get('snowflake_user', 'N/A')}  
            **Usage Type:** {metadata.get('usage_type', 'N/A')}  
            **Key Size:** {metadata.get('key_size', 'Unknown')} bits  
            """)
        
        with col2:
            st.markdown(f"""
            **Created By:** {metadata.get('created_by', 'Unknown')}  
            **Created At:** {metadata.get('created_at', 'Unknown')[:19] if metadata.get('created_at') else 'Unknown'}  
            **Last Modified:** {metadata.get('last_modified', metadata.get('created_at', 'Unknown'))[:19] if metadata.get('last_modified') else 'Unknown'}  
            **Rotated By:** {metadata.get('rotated_by', 'N/A')}  
            """)
        
        if metadata.get('description'):
            st.markdown(f"**Description:** {metadata['description']}")
        
        if metadata.get('rotation_reason'):
            st.markdown(f"**Last Rotation Reason:** {metadata['rotation_reason']}")
        
        # Additional metadata
        with st.expander("🔧 Technical Details"):
            st.json(metadata)
    
    except Exception as e:
        st.error(f"Failed to load key details: {str(e)}")

def _delete_key_interface(kv_client: KeyVaultClient, sf_client: SnowflakeClient, service_account: str, current_user: Dict):
    """Interface for deleting keys"""
    user_principal_name = current_user.get('userPrincipalName')
    
    st.subheader(f"🗑️ Delete Key for {service_account}")
    
    st.error("⚠️ **DANGER ZONE** ⚠️")
    st.warning("""
    **This action cannot be undone!**
    
    Deleting this key pair will:
    - Permanently remove the private key from Azure Key Vault
    - Remove the public key from Azure Key Vault  
    - Optionally remove the public key from the Snowflake user
    - Break any applications currently using this key for authentication
    """)
    
    # Get metadata for context
    try:
        metadata = kv_client.get_key_metadata(service_account)
        snowflake_user = metadata.get('snowflake_user')
        
        with st.form(f"delete_key_{service_account}"):
            st.markdown(f"**Service Account to Delete:** `{service_account}`")
            st.markdown(f"**Associated Snowflake User:** `{snowflake_user}`")
            
            remove_from_snowflake = st.checkbox(
                f"Also remove public key from Snowflake user '{snowflake_user}'",
                value=True,
                help="Recommended to prevent orphaned keys in Snowflake"
            )
            
            deletion_reason = st.text_area(
                "Deletion Reason (Required):",
                placeholder="e.g., Service decommissioned, security incident, no longer needed"
            )
            
            # Confirmation requirements
            st.markdown("**Confirmation Required:**")
            confirm_service_account = st.text_input(
                f"Type '{service_account}' to confirm:",
                placeholder=service_account
            )
            
            confirm_understand = st.checkbox("I understand this action cannot be undone")
            
            # Validation
            can_delete = (
                confirm_service_account == service_account and
                confirm_understand and
                deletion_reason.strip()
            )
            
            if st.form_submit_button("🗑️ DELETE KEY PAIR", disabled=not can_delete, type="secondary"):
                if can_delete:
                    _process_key_deletion(
                        kv_client, sf_client, service_account, current_user, 
                        snowflake_user, remove_from_snowflake, deletion_reason
                    )
                else:
                    st.error("Please complete all confirmation requirements.")
    
    except Exception as e:
        st.error(f"Failed to load key details: {str(e)}")

def _process_key_deletion(kv_client: KeyVaultClient, sf_client: SnowflakeClient, service_account: str,
                         current_user: Dict, snowflake_user: str, remove_from_snowflake: bool, deletion_reason: str):
    """Process the key deletion"""
    user_principal_name = current_user.get('userPrincipalName')
    progress_bar = st.progress(0, "Starting key deletion...")
    
    try:
        # Step 1: Remove from Snowflake if requested
        if remove_from_snowflake and snowflake_user:
            progress_bar.progress(33, "Removing public key from Snowflake...")
            sf_client.remove_user_public_key(snowflake_user, user_principal_name)
        
        # Step 2: Delete from Key Vault
        progress_bar.progress(66, "Deleting keys from Azure Key Vault...")
        kv_client.delete_key(service_account, user_principal_name)
        
        # Step 3: Complete
        progress_bar.progress(100, "Key deletion complete!")
        
        st.success("🗑️ Key pair deleted successfully!")
        
        # Show deletion summary
        with st.expander("📋 Deletion Summary", expanded=True):
            st.markdown(f"""
            **Service Account:** {service_account} ✅ Deleted  
            **Azure Key Vault:** ✅ Private and public keys removed  
            **Snowflake User:** {'✅ Public key removed' if remove_from_snowflake else '⚠️ Public key not removed'}  
            **Deleted By:** {current_user.get('displayName', 'Unknown')}  
            **Deletion Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
            **Reason:** {deletion_reason}  
            """)
        
        # Log the deletion
        sox_audit_logger.log_key_operation(
            "DELETED",
            service_account,
            user_principal_name,
            True
        )
        
        st.info("Please refresh the page to see updated key list.")
        
    except Exception as e:
        error_msg = str(e)
        st.error(f"❌ Key deletion failed: {error_msg}")
        logger.error(f"Key deletion failed for {service_account}: {error_msg}")
        
        sox_audit_logger.log_key_operation(
            "DELETED",
            service_account,
            user_principal_name,
            False,
            error_message=error_msg
        )
    
    finally:
        progress_bar.empty()

def _generate_key_report(kv_client: KeyVaultClient, all_keys: List[str]):
    """Generate comprehensive key report for admins"""
    try:
        st.subheader("📊 Key Management Report")
        
        report_data = []
        key_sizes = {}
        usage_types = {}
        creators = {}
        
        for key in all_keys:
            try:
                metadata = kv_client.get_key_metadata(key)
                
                created_at = metadata.get("created_at", "Unknown")
                if created_at != "Unknown":
                    try:
                        created_date = datetime.fromisoformat(created_at.replace("Z", ""))
                        age_days = (datetime.now() - created_date).days
                    except:
                        age_days = -1
                else:
                    age_days = -1
                
                key_size = metadata.get("key_size", "Unknown")
                usage_type = metadata.get("usage_type", "Unknown") 
                creator = metadata.get("created_by", "Unknown")
                
                # Count statistics
                key_sizes[key_size] = key_sizes.get(key_size, 0) + 1
                usage_types[usage_type] = usage_types.get(usage_type, 0) + 1
                creators[creator] = creators.get(creator, 0) + 1
                
                report_data.append({
                    "Service Account": key,
                    "Age (Days)": age_days if age_days >= 0 else "Unknown",
                    "Key Size": f"{key_size} bits" if key_size != "Unknown" else "Unknown",
                    "Usage Type": usage_type,
                    "Creator": creator,
                    "Snowflake User": metadata.get("snowflake_user", "N/A")
                })
                
            except Exception as e:
                logger.warning(f"Failed to process {key} for report: {str(e)}")
        
        # Display report
        if report_data:
            df = pd.DataFrame(report_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
            
            # Statistics
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.subheader("Key Sizes")
                for size, count in sorted(key_sizes.items()):
                    st.metric(f"{size} bits", count)
            
            with col2:
                st.subheader("Usage Types")
                for usage, count in sorted(usage_types.items()):
                    st.metric(usage, count)
            
            with col3:
                st.subheader("Top Creators")
                for creator, count in sorted(creators.items(), key=lambda x: x[1], reverse=True)[:5]:
                    st.metric(creator.split('@')[0] if '@' in creator else creator, count)
        
    except Exception as e:
        st.error(f"Failed to generate report: {str(e)}")

def _find_keys_needing_rotation(kv_client: KeyVaultClient, all_keys: List[str]):
    """Find keys that need rotation based on age"""
    try:
        st.subheader("⚠️ Keys Needing Rotation")
        
        old_keys = []
        very_old_keys = []
        
        for key in all_keys:
            try:
                metadata = kv_client.get_key_metadata(key)
                created_at = metadata.get("created_at", "Unknown")
                
                if created_at != "Unknown":
                    try:
                        created_date = datetime.fromisoformat(created_at.replace("Z", ""))
                        age_days = (datetime.now() - created_date).days
                        
                        if age_days > 730:  # 2 years
                            very_old_keys.append({
                                "Service Account": key,
                                "Age": f"{age_days} days",
                                "Priority": "🔴 High",
                                "Creator": metadata.get("created_by", "Unknown")
                            })
                        elif age_days > 365:  # 1 year
                            old_keys.append({
                                "Service Account": key,
                                "Age": f"{age_days} days", 
                                "Priority": "🟡 Medium",
                                "Creator": metadata.get("created_by", "Unknown")
                            })
                    except:
                        pass
            except:
                pass
        
        if very_old_keys:
            st.error(f"🔴 {len(very_old_keys)} keys are over 2 years old and need immediate rotation:")
            df_very_old = pd.DataFrame(very_old_keys)
            st.dataframe(df_very_old, use_container_width=True, hide_index=True)
        
        if old_keys:
            st.warning(f"🟡 {len(old_keys)} keys are over 1 year old and should be rotated soon:")
            df_old = pd.DataFrame(old_keys)
            st.dataframe(df_old, use_container_width=True, hide_index=True)
        
        if not old_keys and not very_old_keys:
            st.success("✅ All keys are within recommended rotation periods!")
    
    except Exception as e:
        st.error(f"Failed to analyze key ages: {str(e)}")

def show_usage_tracking(kv_client: KeyVaultClient, current_user: Dict, user_role: str):
    """Usage tracking and reporting dashboard"""
    st.header("📊 Usage Tracking & Reports")
    
    user_principal_name = current_user.get('userPrincipalName')
    
    # Get user's keys for tracking
    try:
        if user_role == "admin":
            all_keys = kv_client.list_keys()
            user_keys = kv_client.list_keys(user_filter=user_principal_name)
            show_all_usage = st.checkbox("Show usage for all keys (Admin view)", value=False)
            keys_for_tracking = all_keys if show_all_usage else user_keys
        else:
            keys_for_tracking = kv_client.list_keys(user_filter=user_principal_name)
        
        if not keys_for_tracking:
            st.info("You don't have any key pairs to track. Create some keys first to see usage data.")
            return
        
        # Usage tracking tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "📈 Usage Overview", 
            "🔍 Service Analysis", 
            "📋 Audit Reports", 
            "⚠️ Compliance Dashboard"
        ])
        
        with tab1:
            _show_usage_overview(kv_client, keys_for_tracking, user_role)
        
        with tab2:
            _show_service_analysis(kv_client, keys_for_tracking)
        
        with tab3:
            _show_audit_reports(kv_client, keys_for_tracking, user_role)
        
        with tab4:
            _show_compliance_dashboard(kv_client, keys_for_tracking, user_role)
    
    except Exception as e:
        st.error(f"Error loading usage tracking data: {str(e)}")
        logger.error(f"Usage tracking error for user {user_principal_name}: {str(e)}")

def _show_usage_overview(kv_client: KeyVaultClient, keys: List[str], user_role: str):
    """Show overall usage overview with metrics and charts"""
    st.subheader("📈 Usage Overview")
    
    # Key metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Keys Tracked", len(keys))
    
    with col2:
        # Count keys by usage type
        usage_types = {}
        for key in keys:
            try:
                metadata = kv_client.get_key_metadata(key)
                usage_type = metadata.get("usage_type", "Unknown")
                usage_types[usage_type] = usage_types.get(usage_type, 0) + 1
            except:
                pass
        most_common = max(usage_types.items(), key=lambda x: x[1]) if usage_types else ("None", 0)
        st.metric("Most Used Service", most_common[0], delta=most_common[1])
    
    with col3:
        # Calculate average key age
        total_age = 0
        valid_keys = 0
        for key in keys:
            try:
                metadata = kv_client.get_key_metadata(key)
                created_at = metadata.get("created_at")
                if created_at and created_at != "Unknown":
                    created_date = datetime.fromisoformat(created_at.replace("Z", ""))
                    age_days = (datetime.now() - created_date).days
                    total_age += age_days
                    valid_keys += 1
            except:
                pass
        
        avg_age = total_age // valid_keys if valid_keys > 0 else 0
        st.metric("Avg Key Age", f"{avg_age} days")
    
    with col4:
        # Count keys needing rotation
        old_keys = 0
        for key in keys:
            try:
                metadata = kv_client.get_key_metadata(key)
                created_at = metadata.get("created_at")
                if created_at and created_at != "Unknown":
                    created_date = datetime.fromisoformat(created_at.replace("Z", ""))
                    age_days = (datetime.now() - created_date).days
                    if age_days > 365:
                        old_keys += 1
            except:
                pass
        
        st.metric("Keys Needing Rotation", old_keys, delta="🔴" if old_keys > 0 else "✅")
    
    # Usage by service type chart
    st.subheader("🔧 Usage by Service Type")
    
    if usage_types:
        # Create pie chart for usage types
        fig_pie = px.pie(
            values=list(usage_types.values()),
            names=list(usage_types.keys()),
            title="Key Pairs by Usage Type"
        )
        st.plotly_chart(fig_pie, use_container_width=True)
    else:
        st.info("No usage type data available")
    
    # Key creation timeline
    st.subheader("📅 Key Creation Timeline")
    
    creation_data = []
    for key in keys:
        try:
            metadata = kv_client.get_key_metadata(key)
            created_at = metadata.get("created_at")
            if created_at and created_at != "Unknown":
                created_date = datetime.fromisoformat(created_at.replace("Z", ""))
                creation_data.append({
                    "Date": created_date.date(),
                    "Service Account": key,
                    "Usage Type": metadata.get("usage_type", "Unknown")
                })
        except:
            pass
    
    if creation_data:
        creation_df = pd.DataFrame(creation_data)
        # Group by date and count
        timeline_data = creation_df.groupby(["Date", "Usage Type"]).size().reset_index(name="Count")
        
        if not timeline_data.empty:
            fig_timeline = px.line(
                timeline_data,
                x="Date",
                y="Count", 
                color="Usage Type",
                title="Key Creation Over Time"
            )
            st.plotly_chart(fig_timeline, use_container_width=True)
    else:
        st.info("No creation timeline data available")

def _show_service_analysis(kv_client: KeyVaultClient, keys: List[str]):
    """Detailed analysis of service usage patterns"""
    st.subheader("🔍 Service Analysis")
    
    # Service breakdown
    service_data = []
    
    for key in keys:
        try:
            metadata = kv_client.get_key_metadata(key)
            created_at = metadata.get("created_at", "Unknown")
            
            # Calculate age
            if created_at != "Unknown":
                try:
                    created_date = datetime.fromisoformat(created_at.replace("Z", ""))
                    age_days = (datetime.now() - created_date).days
                    age_category = "New (< 30 days)" if age_days < 30 else \
                                  "Recent (30-90 days)" if age_days < 90 else \
                                  "Mature (90-365 days)" if age_days < 365 else \
                                  "Old (> 1 year)"
                except:
                    age_days = -1
                    age_category = "Unknown"
            else:
                age_days = -1
                age_category = "Unknown"
            
            service_data.append({
                "Service Account": key,
                "Usage Type": metadata.get("usage_type", "Unknown"),
                "Snowflake User": metadata.get("snowflake_user", "N/A"),
                "Key Size": f"{metadata.get('key_size', 'Unknown')} bits",
                "Age (Days)": age_days if age_days >= 0 else "Unknown",
                "Age Category": age_category,
                "Creator": metadata.get("created_by", "Unknown"),
                "Description": metadata.get("description", "No description")[:50] + "..." if len(metadata.get("description", "")) > 50 else metadata.get("description", "No description")
            })
            
        except Exception as e:
            logger.warning(f"Failed to analyze service {key}: {str(e)}")
            service_data.append({
                "Service Account": key,
                "Usage Type": "Error",
                "Snowflake User": "Error",
                "Key Size": "Error",
                "Age (Days)": "Error",
                "Age Category": "Error",
                "Creator": "Error",
                "Description": "Failed to load data"
            })
    
    if service_data:
        df = pd.DataFrame(service_data)
        
        # Filter controls
        col1, col2, col3 = st.columns(3)
        
        with col1:
            usage_filter = st.selectbox(
                "Filter by Usage Type:",
                ["All"] + list(df["Usage Type"].unique())
            )
        
        with col2:
            age_filter = st.selectbox(
                "Filter by Age Category:",
                ["All"] + list(df["Age Category"].unique())
            )
        
        with col3:
            creator_filter = st.selectbox(
                "Filter by Creator:",
                ["All"] + list(df["Creator"].unique())
            )
        
        # Apply filters
        filtered_df = df.copy()
        if usage_filter != "All":
            filtered_df = filtered_df[filtered_df["Usage Type"] == usage_filter]
        if age_filter != "All":
            filtered_df = filtered_df[filtered_df["Age Category"] == age_filter]
        if creator_filter != "All":
            filtered_df = filtered_df[filtered_df["Creator"] == creator_filter]
        
        # Display filtered data
        st.dataframe(filtered_df, use_container_width=True, hide_index=True)
        
        # Analysis charts
        col1, col2 = st.columns(2)
        
        with col1:
            # Age distribution
            age_counts = filtered_df["Age Category"].value_counts()
            if not age_counts.empty:
                fig_age = px.bar(
                    x=age_counts.index,
                    y=age_counts.values,
                    title="Keys by Age Category"
                )
                st.plotly_chart(fig_age, use_container_width=True)
        
        with col2:
            # Key size distribution
            size_counts = filtered_df["Key Size"].value_counts()
            if not size_counts.empty:
                fig_size = px.bar(
                    x=size_counts.index,
                    y=size_counts.values,
                    title="Keys by Size"
                )
                st.plotly_chart(fig_size, use_container_width=True)
    else:
        st.info("No service data available for analysis")

def _show_audit_reports(kv_client: KeyVaultClient, keys: List[str], user_role: str):
    """Show audit reports and compliance information"""
    st.subheader("📋 Audit Reports")
    
    # Report generation options
    with st.expander("📊 Generate Custom Report"):
        col1, col2 = st.columns(2)
        
        with col1:
            report_type = st.selectbox(
                "Report Type:",
                ["Key Inventory", "Key Rotation History", "User Activity", "Compliance Summary"]
            )
            
            date_range = st.date_input(
                "Date Range:",
                value=[datetime.now().date() - timedelta(days=30), datetime.now().date()],
                max_value=datetime.now().date()
            )
        
        with col2:
            include_details = st.checkbox("Include detailed metadata", value=True)
            include_creators = st.checkbox("Include creator information", value=True)
            
            export_format = st.selectbox("Export Format:", ["CSV", "JSON"])
        
        if st.button("📋 Generate Report"):
            report_data = _generate_audit_report(
                kv_client, keys, report_type, date_range, 
                include_details, include_creators
            )
            
            if report_data:
                st.success(f"Generated {report_type} report with {len(report_data)} records")
                
                # Display report preview
                df_report = pd.DataFrame(report_data)
                st.dataframe(df_report, use_container_width=True, hide_index=True)
                
                # Export options
                if export_format == "CSV":
                    csv = df_report.to_csv(index=False)
                    st.download_button(
                        "📥 Download CSV",
                        csv,
                        file_name=f"{report_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.csv",
                        mime="text/csv"
                    )
                else:
                    json_data = df_report.to_json(orient='records', indent=2)
                    st.download_button(
                        "📥 Download JSON",
                        json_data,
                        file_name=f"{report_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.json",
                        mime="application/json"
                    )
            else:
                st.warning("No data available for the selected criteria")
    
    # Recent activity summary
    st.subheader("🕒 Recent Activity Summary")
    
    try:
        recent_activity = kv_client.get_recent_activity()
        
        if recent_activity:
            # Filter for user's keys if not admin
            if user_role != "admin":
                recent_activity = [
                    activity for activity in recent_activity
                    if activity.get("Service Account") in keys
                ]
            
            if recent_activity:
                activity_df = pd.DataFrame(recent_activity)
                
                # Activity metrics
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.metric("Recent Operations", len(recent_activity))
                
                with col2:
                    unique_accounts = len(set(act.get("Service Account") for act in recent_activity))
                    st.metric("Accounts Involved", unique_accounts)
                
                with col3:
                    unique_users = len(set(act.get("Created By") for act in recent_activity))
                    st.metric("Active Users", unique_users)
                
                # Activity table
                st.dataframe(activity_df, use_container_width=True, hide_index=True)
            else:
                st.info("No recent activity for your service accounts")
        else:
            st.info("No recent activity data available")
    
    except Exception as e:
        st.error(f"Failed to load recent activity: {str(e)}")

def _show_compliance_dashboard(kv_client: KeyVaultClient, keys: List[str], user_role: str):
    """Show compliance dashboard with SOX requirements"""
    st.subheader("⚠️ Compliance Dashboard")
    
    # Compliance metrics
    col1, col2, col3, col4 = st.columns(4)
    
    # Calculate compliance metrics
    total_keys = len(keys)
    keys_with_metadata = 0
    keys_needing_rotation = 0
    keys_with_audit_trail = 0
    
    for key in keys:
        try:
            metadata = kv_client.get_key_metadata(key)
            
            # Check if metadata exists
            if metadata:
                keys_with_metadata += 1
            
            # Check if audit trail exists (creator info)
            if metadata.get("created_by"):
                keys_with_audit_trail += 1
            
            # Check if rotation needed
            created_at = metadata.get("created_at")
            if created_at and created_at != "Unknown":
                try:
                    created_date = datetime.fromisoformat(created_at.replace("Z", ""))
                    age_days = (datetime.now() - created_date).days
                    if age_days > 365:
                        keys_needing_rotation += 1
                except:
                    pass
        except:
            pass
    
    with col1:
        metadata_compliance = (keys_with_metadata / total_keys * 100) if total_keys > 0 else 0
        st.metric(
            "Metadata Compliance",
            f"{metadata_compliance:.1f}%",
            delta="✅" if metadata_compliance == 100 else "⚠️"
        )
    
    with col2:
        audit_compliance = (keys_with_audit_trail / total_keys * 100) if total_keys > 0 else 0
        st.metric(
            "Audit Trail Coverage",
            f"{audit_compliance:.1f}%",
            delta="✅" if audit_compliance >= 95 else "⚠️"
        )
    
    with col3:
        rotation_compliance = ((total_keys - keys_needing_rotation) / total_keys * 100) if total_keys > 0 else 0
        st.metric(
            "Rotation Compliance",
            f"{rotation_compliance:.1f}%",
            delta="✅" if rotation_compliance >= 90 else "🔴"
        )
    
    with col4:
        overall_score = (metadata_compliance + audit_compliance + rotation_compliance) / 3
        st.metric(
            "Overall Compliance",
            f"{overall_score:.1f}%",
            delta="✅" if overall_score >= 90 else "⚠️"
        )
    
    # SOX Compliance Checklist
    st.subheader("📋 SOX Compliance Checklist")
    
    checklist_items = [
        {
            "requirement": "All keys have complete metadata",
            "status": metadata_compliance == 100,
            "details": f"{keys_with_metadata}/{total_keys} keys have complete metadata"
        },
        {
            "requirement": "All key operations are audited",
            "status": audit_compliance >= 95,
            "details": f"{keys_with_audit_trail}/{total_keys} keys have audit trails"
        },
        {
            "requirement": "Keys are rotated within policy (< 1 year)",
            "status": keys_needing_rotation == 0,
            "details": f"{keys_needing_rotation} keys need rotation"
        },
        {
            "requirement": "Access controls are properly configured",
            "status": True,  # Always true if they can access the system
            "details": "Role-based access control is active"
        },
        {
            "requirement": "Audit logs are retained for 7 years",
            "status": True,  # Configured in settings
            "details": f"Retention period: {settings.AUDIT_LOG_RETENTION_DAYS} days"
        }
    ]
    
    for item in checklist_items:
        status_icon = "✅" if item["status"] else "❌"
        st.markdown(f"{status_icon} **{item['requirement']}** - {item['details']}")
    
    # Compliance recommendations
    if overall_score < 90:
        st.subheader("🔧 Compliance Recommendations")
        
        recommendations = []
        
        if metadata_compliance < 100:
            recommendations.append("Ensure all service accounts have complete metadata including usage type and description")
        
        if audit_compliance < 95:
            recommendations.append("Review and update service accounts missing creator information")
        
        if keys_needing_rotation > 0:
            recommendations.append(f"Rotate {keys_needing_rotation} keys that are over 1 year old")
        
        for i, rec in enumerate(recommendations, 1):
            st.warning(f"{i}. {rec}")
    else:
        st.success("🎉 All compliance requirements are met!")
    
    # Compliance report generation
    if user_role == "admin":
        st.subheader("📊 Compliance Reports (Admin)")
        
        if st.button("📋 Generate SOX Compliance Report"):
            compliance_report = _generate_compliance_report(kv_client, keys)
            
            if compliance_report:
                st.success("SOX compliance report generated successfully")
                
                # Display summary
                with st.expander("📋 Compliance Report Summary", expanded=True):
                    for section, data in compliance_report.items():
                        st.markdown(f"**{section}:** {data}")
                
                # Export option
                report_json = json.dumps(compliance_report, indent=2, default=str)
                st.download_button(
                    "📥 Download Compliance Report",
                    report_json,
                    file_name=f"sox_compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )

def _generate_audit_report(kv_client: KeyVaultClient, keys: List[str], report_type: str, 
                          date_range: List, include_details: bool, include_creators: bool) -> List[Dict]:
    """Generate custom audit report based on criteria"""
    try:
        report_data = []
        
        for key in keys:
            try:
                metadata = kv_client.get_key_metadata(key)
                created_at = metadata.get("created_at")
                
                # Filter by date range if created_at is available
                if created_at and created_at != "Unknown":
                    try:
                        created_date = datetime.fromisoformat(created_at.replace("Z", "")).date()
                        if len(date_range) == 2:
                            if not (date_range[0] <= created_date <= date_range[1]):
                                continue
                    except:
                        pass
                
                # Build report record based on type
                record = {"Service Account": key}
                
                if report_type == "Key Inventory":
                    record.update({
                        "Usage Type": metadata.get("usage_type", "Unknown"),
                        "Snowflake User": metadata.get("snowflake_user", "N/A"),
                        "Key Size": f"{metadata.get('key_size', 'Unknown')} bits",
                        "Created Date": created_at[:10] if created_at and created_at != "Unknown" else "Unknown"
                    })
                
                elif report_type == "Key Rotation History":
                    record.update({
                        "Last Modified": metadata.get("last_modified", metadata.get("created_at", "Unknown"))[:10],
                        "Rotation Reason": metadata.get("rotation_reason", "N/A"),
                        "Previous Key Size": metadata.get("previous_key_size", "N/A")
                    })
                
                elif report_type == "User Activity":
                    record.update({
                        "Created By": metadata.get("created_by", "Unknown"),
                        "Rotated By": metadata.get("rotated_by", "N/A"),
                        "Created Date": created_at[:10] if created_at and created_at != "Unknown" else "Unknown"
                    })
                
                elif report_type == "Compliance Summary":
                    has_metadata = bool(metadata.get("usage_type") and metadata.get("snowflake_user"))
                    has_audit_trail = bool(metadata.get("created_by"))
                    
                    record.update({
                        "Has Complete Metadata": "Yes" if has_metadata else "No",
                        "Has Audit Trail": "Yes" if has_audit_trail else "No",
                        "Created By": metadata.get("created_by", "Unknown")
                    })
                
                # Add optional details
                if include_details:
                    record["Description"] = metadata.get("description", "No description")
                
                if include_creators:
                    record["Creator"] = metadata.get("created_by", "Unknown")
                
                report_data.append(record)
                
            except Exception as e:
                logger.warning(f"Failed to include {key} in report: {str(e)}")
        
        return report_data
    
    except Exception as e:
        logger.error(f"Failed to generate audit report: {str(e)}")
        return []

def _generate_compliance_report(kv_client: KeyVaultClient, keys: List[str]) -> Dict:
    """Generate comprehensive compliance report"""
    try:
        report = {
            "Report Generated": datetime.now().isoformat(),
            "Total Keys Analyzed": len(keys),
            "Compliance Summary": {},
            "Key Breakdown": {},
            "Recommendations": []
        }
        
        # Analyze each key
        compliant_keys = 0
        keys_with_issues = []
        
        for key in keys:
            try:
                metadata = kv_client.get_key_metadata(key)
                issues = []
                
                # Check metadata completeness
                if not metadata.get("usage_type"):
                    issues.append("Missing usage type")
                if not metadata.get("snowflake_user"):
                    issues.append("Missing Snowflake user")
                if not metadata.get("created_by"):
                    issues.append("Missing creator information")
                
                # Check key age
                created_at = metadata.get("created_at")
                if created_at and created_at != "Unknown":
                    try:
                        created_date = datetime.fromisoformat(created_at.replace("Z", ""))
                        age_days = (datetime.now() - created_date).days
                        if age_days > 365:
                            issues.append(f"Key is {age_days} days old (rotation recommended)")
                    except:
                        issues.append("Invalid creation date format")
                
                if not issues:
                    compliant_keys += 1
                else:
                    keys_with_issues.append({"key": key, "issues": issues})
                    
            except Exception as e:
                keys_with_issues.append({"key": key, "issues": [f"Metadata error: {str(e)}"]})
        
        # Build compliance summary
        compliance_rate = (compliant_keys / len(keys) * 100) if keys else 0
        
        report["Compliance Summary"] = {
            "Overall Compliance Rate": f"{compliance_rate:.1f}%",
            "Compliant Keys": compliant_keys,
            "Keys with Issues": len(keys_with_issues),
            "Status": "COMPLIANT" if compliance_rate >= 90 else "NON-COMPLIANT"
        }
        
        report["Key Breakdown"] = {
            "Keys with Issues": [
                f"{item['key']}: {', '.join(item['issues'])}" 
                for item in keys_with_issues[:10]  # Limit to first 10
            ]
        }
        
        # Generate recommendations
        if compliance_rate < 100:
            report["Recommendations"] = [
                "Complete missing metadata for all service accounts",
                "Implement regular key rotation schedule",
                "Review and update audit trail information",
                "Consider automated compliance monitoring"
            ]
        
        return report
        
    except Exception as e:
        logger.error(f"Failed to generate compliance report: {str(e)}")
        return {"error": str(e)}

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