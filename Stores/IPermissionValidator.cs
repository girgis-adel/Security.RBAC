using Microsoft.AspNetCore.Identity;

namespace Security.RBAC.Stores;

public interface IPermissionValidator<TPermission>
    where TPermission : class
{
    Task<IdentityResult> ValidateAsync(PermissionManager<TPermission> manager, TPermission permission);
}
