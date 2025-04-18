using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Security.RBAC.Constants;

namespace Security.RBAC.Authorization;

public class RbacPermissionPolicyProvider(IOptions<AuthorizationOptions> options) : IAuthorizationPolicyProvider
{
    private readonly DefaultAuthorizationPolicyProvider fallbackPolicyProvider
        = new(options);

    public Task<AuthorizationPolicy> GetDefaultPolicyAsync()
        => fallbackPolicyProvider.GetDefaultPolicyAsync();

    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync()
        => fallbackPolicyProvider.GetFallbackPolicyAsync();

    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        if (policyName.StartsWith(RbacPermissionsConstants.PermissionsPolicyPrefix, StringComparison.OrdinalIgnoreCase))
        {
            var permissionPart = policyName[(RbacPermissionsConstants.PermissionsPolicyPrefix.Length + 1)..];
            var requiredPermissions = permissionPart.Split(",", StringSplitOptions.RemoveEmptyEntries);

            var policy = new AuthorizationPolicyBuilder();
            policy.AddRequirements(new HasRbacPermissionsRequirement(requiredPermissions));

            return Task.FromResult<AuthorizationPolicy?>(policy.Build());
        }

        return fallbackPolicyProvider.GetPolicyAsync(policyName);
    }
}
