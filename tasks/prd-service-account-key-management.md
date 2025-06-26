# Product Requirements Document: Service Account Key Management Portal

## Introduction/Overview

The Service Account Key Management Portal is a web-based application designed to eliminate the burden on Technical Application Owners (TAOs) who currently need to manually install OpenSSH, generate SSH key pairs, and manage secure storage. This portal provides a centralized, automated solution for RSA key-pair generation, secure storage in Azure Key Vault, and seamless integration with Snowflake user accounts. The system addresses both security compliance requirements and operational efficiency by providing a self-service portal that reduces platform team support requests.

## Goals

1. **Eliminate Manual SSH Key Generation**: Remove the need for TAOs to install OpenSSH and manually create key pairs
2. **Centralize Key Management**: Provide a single portal for all service account key operations
3. **Ensure Security Compliance**: Meet SOX compliance requirements with proper audit trails and secure storage
4. **Reduce Platform Team Burden**: Decrease support requests related to SSH key setup and management
5. **Maintain Service Continuity**: Ensure uninterrupted service operation during key rotations and updates
6. **Integrate with Existing Infrastructure**: Seamlessly work with Azure Key Vault, Snowflake, and Active Directory

## User Stories

1. **As a TAO**, I want to generate RSA key pairs through a web portal so that I don't need to install OpenSSH locally
2. **As a TAO**, I want my service account keys automatically stored in Azure Key Vault so that I don't need to manage secure storage myself
3. **As a TAO**, I want the public key automatically updated in Snowflake so that my service account can connect immediately
4. **As a TAO**, I want to view all my service account keys in one place so that I can track what's deployed
5. **As a TAO**, I want to rotate keys when needed so that I can maintain security compliance
6. **As a TAO**, I want to download public keys when needed so that I can configure other systems
7. **As a Platform Team Member**, I want audit trails of all key operations so that I can meet SOX compliance requirements
8. **As a Platform Team Member**, I want role-based access controls so that only authorized TAOs can manage specific service accounts

## Functional Requirements

1. **Key Generation**
   1. The system must generate RSA key pairs (2048-bit minimum)
   2. The system must store private keys securely in Azure Key Vault
   3. The system must store public keys in Azure Key Vault for backup/reference
   4. The system must automatically update Snowflake user accounts with the new public key

2. **User Authentication & Authorization**
   5. The system must authenticate users via Active Directory integration
   6. The system must implement role-based access controls
   7. The system must restrict TAOs to only their assigned service accounts

3. **Key Management Operations**
   8. The system must allow TAOs to view all their service account keys
   9. The system must allow TAOs to rotate existing keys
   10. The system must allow TAOs to download public keys in PEM format
   11. The system must allow TAOs to delete keys when service accounts are decommissioned

4. **Service Integration**
   12. The system must integrate with Azure Key Vault for secure storage
   13. The system must integrate with Snowflake to update user public keys
   14. The system must support key usage by PowerBI, Tableau, Python scripts, and Power Apps
   15. The system must work with any unattended login scenarios via service accounts

5. **Audit & Compliance**
   16. The system must log all key operations (create, rotate, delete, download)
   17. The system must maintain audit trails suitable for SOX compliance
   18. The system must include timestamps and user identification in all audit logs
   19. The system must prevent unauthorized access to audit logs

6. **User Interface**
   20. The system must provide a web-based dashboard showing all service account keys
   21. The system must display key metadata (creation date, last rotation, usage type)
   22. The system must provide clear status indicators for key operations
   23. The system must show error messages and success confirmations

## Non-Goals (Out of Scope)

1. **Multi-Algorithm Support**: Will not support ECDSA, Ed25519, or other key types - RSA only
2. **Approval Workflows**: Will not include approval processes for key operations
3. **Real-Time Monitoring**: Will not provide real-time usage dashboards or alerts
4. **External User Support**: Will not support external clients or partners
5. **Manual Key Import**: Will not allow importing externally generated keys
6. **Cross-Platform Key Sync**: Will not sync keys to systems other than Snowflake automatically

## Design Considerations

1. **Technology Stack**: Use Streamlit for rapid development and ease of use
2. **Security**: All keys stored in Azure Key Vault, never displayed in plaintext in UI
3. **User Experience**: Simple, intuitive interface suitable for TAOs with varying technical expertise
4. **Responsive Design**: Must work on desktop and tablet devices
5. **Error Handling**: Clear error messages with actionable guidance

## Technical Considerations

1. **Azure Integration**: Must use Azure Key Vault SDK and Managed Identity for authentication
2. **Snowflake Integration**: Must use Snowflake Python connector for public key updates
3. **Active Directory**: Must integrate with Azure AD for user authentication
4. **Database**: Use Azure Key Vault metadata storage rather than separate database
5. **Deployment**: Should be deployable as a container in Azure App Service
6. **Logging**: Integrate with Azure Monitor/Log Analytics for compliance logging

## Success Metrics

1. **Adoption Rate**: 80% of TAOs using the portal within 6 months of launch
2. **Support Reduction**: 70% reduction in platform team tickets related to SSH key setup
3. **Compliance**: 100% of key operations logged and auditable for SOX compliance
4. **User Satisfaction**: Average user satisfaction score of 4.0/5.0 or higher
5. **Service Continuity**: Zero service interruptions due to key rotation failures

## Open Questions

1. **Key Rotation Schedule**: Should we implement automated key rotation on a schedule (e.g., every 90 days)?
2. **Notification System**: Do we need email notifications for key operations or expiration warnings?
3. **Backup Strategy**: What is the disaster recovery plan for Azure Key Vault outages?
4. **Performance Requirements**: What is the expected concurrent user load?
5. **Integration Testing**: How will we test Snowflake integration without affecting production?