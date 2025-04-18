using Microsoft.AspNetCore.Identity;

namespace Security.RBAC.Stores;

public class PermissionValidator<TPermission> : IPermissionValidator<TPermission>
    where TPermission : class
{
    public virtual async Task<IdentityResult> ValidateAsync(PermissionManager<TPermission> manager, TPermission permission)
    {
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(permission);
        var errors = await PermissionValidator<TPermission>.ValidatePermissionName(manager, permission).ConfigureAwait(false);
        if (errors?.Count > 0)
        {
            return IdentityResult.Failed([.. errors]);
        }
        return IdentityResult.Success;
    }

    private static async Task<List<IdentityError>?> ValidatePermissionName(PermissionManager<TPermission> manager, TPermission permission)
    {
        List<IdentityError>? errors = null;
        var permissionName = await manager.GetPermissionNameAsync(permission).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(permissionName))
        {
            errors ??= [];
            errors.Add(new IdentityError
            {
                Code = "InvalidPermissionName",
                Description = $"Permission name '{permissionName}' is invalid."
            });
        }
        else
        {
            var owner = await manager.FindByNameAsync(permissionName).ConfigureAwait(false);
            if (owner != null &&
                !string.Equals(await manager.GetPermissionIdAsync(owner).ConfigureAwait(false), await manager.GetPermissionIdAsync(permission).ConfigureAwait(false)))
            {
                errors ??= [];
                errors.Add(new IdentityError
                {
                    Code = "DuplicatePermissionName",
                    Description = $"Permission name '{permissionName}' is already taken."
                });
            }
        }
        return errors;
    }
}
