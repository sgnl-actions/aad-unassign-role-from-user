/**
 * Azure AD Unassign Role from User Action
 *
 * Removes a directory role from a user in Azure Active Directory using a two-step process:
 * 1. Get user's directory object ID by user principal name
 * 2. Create role assignment schedule request to remove the role assignment
 */

import { getBaseURL, createAuthHeaders, resolveJSONPathTemplates} from '@sgnl-actions/utils';

/**
 * Helper function to get user by UPN and remove role assignment
 * @param {string} userPrincipalName - User principal name
 * @param {string} roleId - Role definition ID
 * @param {string} directoryScopeId - Directory scope ID
 * @param {string} justification - Justification for removal
 * @param {string} address - Azure AD base URL (without trailing slash)
 * @param {Object} headers - Request headers with Authorization
 * @returns {Promise<Object>} API response
 */
async function unassignRoleFromUser(userPrincipalName, roleId, directoryScopeId, justification, address, headers) {
  // Step 1: Get user by UPN to retrieve their directory object ID
  const encodedUPN = encodeURIComponent(userPrincipalName);
  const getUserUrl = `${address}/v1.0/users/${encodedUPN}`;

  const getUserResponse = await fetch(getUserUrl, {
    method: 'GET',
    headers
  });

  if (!getUserResponse.ok) {
    throw new Error(`Failed to get user ${userPrincipalName}: ${getUserResponse.status} ${getUserResponse.statusText}`);
  }

  const userData = await getUserResponse.json();
  const userId = userData.id;

  // Step 2: Create role assignment schedule request for removal
  const unassignRoleUrl = `${address}/v1.0/roleManagement/directory/roleAssignmentScheduleRequests`;

  const roleRemovalRequest = {
    action: 'adminRemove',
    justification: justification,
    roleDefinitionId: roleId,
    directoryScopeId: directoryScopeId,
    principalId: userId,
    scheduleInfo: {
      startDateTime: new Date().toISOString()
    }
  };

  const unassignRoleResponse = await fetch(unassignRoleUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify(roleRemovalRequest)
  });

  if (!unassignRoleResponse.ok) {
    throw new Error(`Failed to remove role ${roleId} from user ${userPrincipalName}: ${unassignRoleResponse.status} ${unassignRoleResponse.statusText}`);
  }

  const removalData = await unassignRoleResponse.json();

  return {
    userId,
    requestId: removalData.id,
    removalData
  };
}

export default {
  /**
   * Main execution handler - removes role from user
   * @param {Object} resolvedParams - Job input parameters
   * @param {string} resolvedParams.userPrincipalName - User principal name
   * @param {string} resolvedParams.roleId - Role definition ID
   * @param {string} resolvedParams.directoryScopeId - Directory scope ID (default: "/")
   * @param {string} resolvedParams.justification - Justification for removal (default: "Removed by SGNL.ai")
   * @param {Object} context - Execution context with env, secrets, outputs
   * @param {string} context.environment.ADDRESS - Azure AD API base URL
   *
   * The configured auth type will determine which of the following environment variables and secrets are available
   * @param {string} context.secrets.OAUTH2_CLIENT_CREDENTIALS_CLIENT_SECRET
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUDIENCE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_AUTH_STYLE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_CLIENT_ID
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_SCOPE
   * @param {string} context.environment.OAUTH2_CLIENT_CREDENTIALS_TOKEN_URL
   *
   * @param {string} context.secrets.OAUTH2_AUTHORIZATION_CODE_ACCESS_TOKEN
   *
   * @returns {Object} Removal results
   */
  invoke: async (params, context) => {
    console.log('Starting Azure AD role removal');

    const jobContext = context.data || {};

    // Resolve JSONPath templates in params
    const { result: resolvedParams, errors } = resolveJSONPathTemplates(params, jobContext);
    if (errors.length > 0) {
      console.warn('Template resolution errors:', errors);
    }

    // Validate required parameters
    if (!resolvedParams.userPrincipalName) {
      throw new Error('userPrincipalName is required');
    }

    if (!resolvedParams.roleId) {
      throw new Error('roleId is required');
    }

    // Extract parameters with defaults
    const {
      userPrincipalName,
      roleId,
      directoryScopeId = '/',
      justification = 'Removed by SGNL.ai'
    } = resolvedParams;

    // Get base URL and auth headers using shared utilities
    const address = getBaseURL(resolvedParams, context);
    const headers = await createAuthHeaders(context);

    console.log(`Removing role ${roleId} from user ${userPrincipalName} with scope ${directoryScopeId}`);

    try {
      const result = await unassignRoleFromUser(
        userPrincipalName,
        roleId,
        directoryScopeId,
        justification,
        address,
        headers
      );

      console.log(`Successfully removed role from user. Request ID: ${result.requestId}`);

      return {
        status: 'success',
        userPrincipalName,
        roleId,
        userId: result.userId,
        requestId: result.requestId
      };
    } catch (error) {
      console.error(`Failed to remove role: ${error.message}`);
      throw error;
    }
  },

  /**
   * Error recovery handler - framework handles retries by default
   * Only implement if custom recovery logic is needed
   * @param {Object} params - Original params plus error information
   * @param {Object} context - Execution context
   * @returns {Object} Recovery results
   */
  error: async (params, _context) => {
    const { error, userPrincipalName, roleId } = params;
    console.error(`Role removal failed for user ${userPrincipalName} with role ${roleId}: ${error.message}`);

    // Framework handles retries for transient errors (429, 502, 503, 504)
    // Just re-throw the error to let the framework handle it
    throw error;
  },

  /**
   * Graceful shutdown handler - performs cleanup
   * @param {Object} params - Original params plus halt reason
   * @param {Object} context - Execution context
   * @returns {Object} Cleanup results
   */
  halt: async (params, _context) => {
    const { reason } = params;
    console.log(`Role removal is being halted: ${reason}`);

    return {
      status: 'halted',
      reason: reason,
      halted_at: new Date().toISOString()
    };
  }
};