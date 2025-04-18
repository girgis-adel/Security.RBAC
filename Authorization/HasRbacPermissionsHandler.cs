using Microsoft.AspNetCore.Authorization;
using Security.RBAC.Constants;

namespace Security.RBAC.Authorization;

public class HasRbacPermissionsHandler : AuthorizationHandler<HasRbacPermissionsRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, 
        HasRbacPermissionsRequirement requirement)
    {
        var userPermissions = context.User
            .FindAll(RbacPermissionsConstants.PermissionClaimType)
            .Select(c => c.Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (requirement.RequiredPermissions.Any(p => userPermissions.Contains(p)))
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
