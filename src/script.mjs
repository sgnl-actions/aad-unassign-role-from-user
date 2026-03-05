/**
 * Azure AD Unassign Role from User Action
 *
 * Removes a directory role from a user in Azure Active Directory using a three-step process:
 * 1. Get user's directory object ID by user principal name
 * 2. Check if the role assignment exists (for idempotency)
 * 3. Create role assignment schedule request to remove the role assignment (only if it exists)
 */

import { getBaseURL, createAuthHeaders } from '@sgnl-actions/utils';

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

  // Step 2: Check if role assignment exists (for idempotency)
  const baseURL = `${address}/v1.0/roleManagement/directory/roleAssignments`;
  const url = new URL(baseURL);
  url.searchParams.set('$filter', `principalId eq '${userId}' and roleDefinitionId eq '${roleId}' and directoryScopeId eq '${directoryScopeId}'`);
  const checkAssignmentUrl = url.toString();

  const checkResponse = await fetch(checkAssignmentUrl, {
    method: 'GET',
    headers
  });

  if (!checkResponse.ok) {
    throw new Error(`Failed to check existing role assignments for user ${userPrincipalName}: ${checkResponse.status} ${checkResponse.statusText}`);
  }

  const existingAssignments = await checkResponse.json();

  // If assignment doesn't exist, return success without attempting removal
  if (!existingAssignments.value || existingAssignments.value.length === 0) {
    return {
      userId,
      requestId: null,
      removalData: null,
      alreadyUnassigned: true,
      message: 'Role assignment not found - already unassigned'
    };
  }

  // Step 3: Create role assignment schedule request for removal (only if assignment exists)
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
    removalData,
    alreadyUnassigned: false
  };
}

export default {
  /**
   * Main execution handler - removes role from user
   * @param {Object} params - Job input parameters
   * @param {string} params.userPrincipalName - User principal name
   * @param {string} params.roleId - Role definition ID
   * @param {string} params.directoryScopeId - Directory scope ID (default: "/")
   * @param {string} params.justification - Justification for removal (default: "Removed by SGNL.ai")
   * @param {string} params.address - The Azure AD API base URL (e.g., https://graph.microsoft.com)
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

    // Extract parameters with defaults
    const {
      userPrincipalName,
      roleId,
      directoryScopeId = '/',
      justification = 'Removed by SGNL.ai'
    } = params;

    // Get base URL and auth headers using shared utilities
    const address = getBaseURL(params, context);
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

      if (result.alreadyUnassigned) {
        console.log(`Role assignment was already removed or never existed. ${result.message}`);
        return {
          status: 'success',
          userPrincipalName,
          roleId,
          userId: result.userId,
          requestId: null,
          alreadyUnassigned: true,
          message: result.message,
          address: address
        };
      } else {
        console.log(`Successfully removed role from user. Request ID: ${result.requestId}`);
        return {
          status: 'success',
          userPrincipalName,
          roleId,
          userId: result.userId,
          requestId: result.requestId,
          alreadyUnassigned: false,
          address: address
        };
      }
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