## Relevant Files

- `app.py` - Main Streamlit application entry point and UI routing
- `utils/auth.py` - Active Directory authentication and authorization logic
- `utils/keyvault_client.py` - Azure Key Vault integration for secure key storage
- `utils/snowflake_client.py` - Snowflake integration for public key updates
- `utils/crypto_utils.py` - RSA key pair generation utilities
- `utils/audit_logger.py` - SOX compliance audit logging functionality
- `config/settings.py` - Application configuration and environment variables
- `requirements.txt` - Python dependencies
- `README.md` - Setup and deployment instructions for local development
- `.env.example` - Environment variable template
- `tests/test_auth.py` - Unit tests for authentication module
- `tests/test_keyvault_client.py` - Unit tests for Key Vault client
- `tests/test_snowflake_client.py` - Unit tests for Snowflake client
- `tests/test_crypto_utils.py` - Unit tests for crypto utilities
- `tests/test_audit_logger.py` - Unit tests for audit logging

### Notes

- Unit tests should typically be placed alongside the code files they are testing
- Use `pytest` to run tests. Running without a path executes all tests found by the pytest configuration
- All sensitive configuration should use environment variables with `.env` file support

## Tasks

- [ ] 1.0 Set up project structure and core dependencies
- [ ] 2.0 Implement Active Directory authentication and role-based access control
- [ ] 3.0 Build Azure Key Vault integration for secure key storage
- [ ] 4.0 Create Snowflake integration for public key management
- [ ] 5.0 Develop RSA key generation and cryptographic utilities
- [ ] 6.0 Implement SOX compliance audit logging
- [ ] 7.0 Build Streamlit user interface and dashboard
- [ ] 8.0 Add comprehensive testing suite
- [ ] 9.0 Configure local development environment and documentation