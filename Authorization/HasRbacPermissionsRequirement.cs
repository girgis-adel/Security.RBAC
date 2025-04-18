using Microsoft.AspNetCore.Authorization;

namespace Security.RBAC.Authorization;

public class HasRbacPermissionsRequirement(IEnumerable<string> permissions) : IAuthorizationRequirement
{
    public IReadOnlyCollection<string> RequiredPermissions { get; } = [.. permissions];
}
