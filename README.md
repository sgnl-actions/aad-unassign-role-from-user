# Azure AD Unassign Role from User

Removes a directory role from a user in Azure Active Directory using the Microsoft Graph API. This action uses a two-step process to remove role assignments from users through the role assignment schedule API.

## Overview

This action performs the following steps:

1. **User Lookup**: Retrieves the user's directory object ID by their User Principal Name (UPN)
2. **Role Removal**: Creates a role assignment schedule request to remove the role assignment using the Microsoft Graph API

The action uses Azure AD's Privileged Identity Management (PIM) role assignment schedule API to remove role assignments with proper audit trails and compliance tracking.

## Prerequisites

- Azure AD tenant with appropriate permissions
- Application registration or service principal with required permissions
- Valid access token with Directory.ReadWrite.All permissions

### Required Permissions

The Azure AD application or service principal must have:
- `Directory.ReadWrite.All` - Required to read user information and manage role assignments
- `RoleManagement.ReadWrite.Directory` - Required to manage directory role assignments

## Configuration

### Secrets

| Name | Description | Required |
|------|-------------|----------|
| `AZURE_AD_TOKEN` | Azure AD access token with Directory.ReadWrite.All permissions | Yes |

### Environment Variables

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `AZURE_AD_TENANT_URL` | Azure AD tenant URL (e.g., https://graph.microsoft.com) | Yes | None |

### Input Parameters

| Name | Type | Description | Required | Default |
|------|------|-------------|----------|---------|
| `userPrincipalName` | string | User Principal Name (UPN) of the user to remove the role from | Yes | None |
| `roleId` | string | Directory role definition ID to remove | Yes | None |
| `directoryScopeId` | string | Directory scope ID for the role assignment to remove | No | "/" |
| `justification` | string | Justification for removing the role assignment | No | "Removed by SGNL.ai" |

### Output Values

| Name | Type | Description |
|------|------|-------------|
| `status` | string | Operation result (success, failed, recovered, etc.) |
| `userPrincipalName` | string | User Principal Name that was processed |
| `roleId` | string | Role ID that was removed |
| `userId` | string | User's directory object ID |
| `requestId` | string | Role removal request ID |

## Usage Examples

### Basic Role Removal

```json
{
  "userPrincipalName": "john.doe@example.com",
  "roleId": "729827e3-9c14-49f7-bb1b-9608f156bbb8"
}
```

### Role Removal with Custom Scope

```json
{
  "userPrincipalName": "admin@example.com",
  "roleId": "62e90394-69f5-4237-9190-012177145e10",
  "directoryScopeId": "/administrativeUnits/12345678-1234-1234-1234-123456789abc",
  "justification": "Removing temporary administrative access after project completion"
}
```

### Common Directory Role IDs

| Role Name | Role ID |
|-----------|---------|
| Global Administrator | 62e90394-69f5-4237-9190-012177145e10 |
| User Administrator | fe930be7-5e62-47db-91af-98c3a49a38b1 |
| Application Administrator | 9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3 |
| Directory Readers | 88d8e3e3-8f55-4a1e-953a-9b9898b8876b |
| Directory Writers | 9360feb5-f418-4baa-8175-e2a00bac4301 |

Note: Role IDs may vary between Azure AD tenants. Use the Microsoft Graph API or Azure Portal to find the correct role IDs for your tenant.

## Error Handling

The action implements comprehensive error handling with automatic retry logic:

### Retryable Errors (Automatic Retry)
- `429` - Rate limited (will wait 5 seconds before retry)
- `502` - Bad gateway
- `503` - Service unavailable  
- `504` - Gateway timeout

### Fatal Errors (No Retry)
- `401` - Unauthorized (invalid or expired token)
- `403` - Forbidden (insufficient permissions)
- `400` - Bad request (invalid parameters)
- `404` - Not found (user or role doesn't exist)

### Error Recovery

The action includes an error handler that:
1. Identifies retryable vs. fatal errors
2. Implements exponential backoff for rate limits
3. Provides clear error messages for troubleshooting

## Development

### Local Testing

```bash
# Install dependencies
npm install

# Run tests
npm test

# Check test coverage (80% minimum required)
npm run test:coverage

# Run locally with test parameters
npm run dev -- --params '{"userPrincipalName": "test@example.com", "roleId": "12345678-1234-1234-1234-123456789abc"}'

# Lint code
npm run lint

# Build distribution
npm run build
```

### Testing with Real Azure AD

For integration testing with a real Azure AD tenant:

1. Create an application registration in Azure AD
2. Grant necessary permissions and admin consent
3. Generate an access token
4. Set environment variables and run tests

```bash
export AZURE_AD_TENANT_URL="https://graph.microsoft.com"
export AZURE_AD_TOKEN="your-access-token"
npm run dev
```

## Security Considerations

- **Token Security**: Never log or expose access tokens in plaintext
- **Principle of Least Privilege**: Only grant necessary permissions to the service principal
- **Audit Logging**: All role removals are logged in Azure AD audit logs
- **Token Expiration**: Monitor token expiration and implement refresh logic
- **Input Validation**: All user inputs are validated and URL-encoded to prevent injection attacks

## API Reference

### Microsoft Graph Endpoints Used

1. **Get User by UPN**
   - `GET /v1.0/users/{userPrincipalName}`
   - Returns user's directory object ID

2. **Create Role Assignment Schedule Request**
   - `POST /v1.0/roleManagement/directory/roleAssignmentScheduleRequests`
   - Removes role assignment

### Request Structure

The role removal request body follows this structure:

```json
{
  "action": "adminRemove",
  "justification": "Removed by SGNL.ai",
  "roleDefinitionId": "role-id",
  "directoryScopeId": "/",
  "principalId": "user-object-id",
  "scheduleInfo": {
    "startDateTime": "2024-01-15T10:30:00.000Z"
  }
}
```

## Troubleshooting

### Common Issues

1. **401 Unauthorized**
   - Check if access token is valid and not expired
   - Verify token has required permissions

2. **403 Forbidden**  
   - Ensure service principal has Directory.ReadWrite.All permissions
   - Verify admin consent has been granted

3. **404 User Not Found**
   - Check if User Principal Name is correct and exists
   - Verify user is not deleted or in recycle bin

4. **400 Bad Request - Role Removal**
   - Verify role ID exists in the tenant
   - Check if user actually has the role assigned
   - Ensure directory scope ID is valid
   - Verify there's an active role assignment to remove

### Debug Tips

- Enable verbose logging to see detailed API requests/responses
- Check Azure AD audit logs for role assignment activity
- Use Graph Explorer to test API calls manually
- Verify permissions using the Microsoft Graph API
- Check existing role assignments before attempting removal

## Compliance and Audit

- All role removals are logged in Azure AD audit logs
- Removal requests include justification for compliance tracking
- Role changes follow your organization's access review policies
- Role assignments can be tracked and managed through Azure AD PIM

## Support

- [Microsoft Graph API Documentation](https://docs.microsoft.com/en-us/graph/)
- [Azure AD Role Management](https://docs.microsoft.com/en-us/graph/api/resources/unifiedroleassignment)
- [SGNL Job Service Documentation](https://github.com/SGNL-ai/job_service)