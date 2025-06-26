import streamlit as st
import pandas as pd
from datetime import datetime
from utils.keyvault_client import KeyVaultClient
from utils.snowflake_client import SnowflakeClient
from utils.crypto_utils import generate_key_pair
from utils.auth import authenticate_user

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
    
    # Initialize clients
    kv_client = KeyVaultClient()
    sf_client = SnowflakeClient()
    
    # Sidebar navigation
    page = st.sidebar.selectbox(
        "Navigation",
        ["Dashboard", "Generate Key-Pair", "Manage Keys", "Usage Tracking"]
    )
    
    if page == "Dashboard":
        show_dashboard(kv_client)
    elif page == "Generate Key-Pair":
        show_generate_keys(kv_client, sf_client)
    elif page == "Manage Keys":
        show_manage_keys(kv_client, sf_client)
    elif page == "Usage Tracking":
        show_usage_tracking()

def show_dashboard(kv_client):
    st.header("Dashboard")
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Key Pairs", len(kv_client.list_keys()))
    
    with col2:
        st.metric("Active Services", 2)  # PowerBI, Tableau
    
    with col3:
        st.metric("Last Updated", datetime.now().strftime("%Y-%m-%d"))
    
    # Recent activity
    st.subheader("Recent Activity")
    activity_data = kv_client.get_recent_activity()
    if activity_data:
        st.dataframe(activity_data)
    else:
        st.info("No recent activity")

def show_generate_keys(kv_client, sf_client):
    st.header("Generate New Key-Pair")
    
    with st.form("generate_keys"):
        service_account = st.text_input("Service Account Name")
        snowflake_user = st.text_input("Snowflake Username")
        usage_type = st.selectbox("Usage Type", ["PowerBI", "Tableau", "Other"])
        description = st.text_area("Description (Optional)")
        
        if st.form_submit_button("Generate Key-Pair"):
            if service_account and snowflake_user:
                with st.spinner("Generating key-pair..."):
                    try:
                        # Generate key pair
                        private_key, public_key = generate_key_pair()
                        
                        # Store in Key Vault
                        kv_client.store_key_pair(
                            service_account, 
                            private_key, 
                            public_key,
                            {
                                "snowflake_user": snowflake_user,
                                "usage_type": usage_type,
                                "description": description,
                                "created_at": datetime.now().isoformat()
                            }
                        )
                        
                        # Update Snowflake user
                        sf_client.update_user_public_key(snowflake_user, public_key)
                        
                        st.success(f"Key-pair generated and configured for {service_account}")
                        
                    except Exception as e:
                        st.error(f"Error generating key-pair: {str(e)}")
            else:
                st.error("Please fill in all required fields")

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