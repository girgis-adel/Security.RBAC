using Microsoft.AspNetCore.Identity;

namespace Security.RBAC.Stores;

public interface IPermissionStore<TPermission> : IDisposable
    where TPermission : class
{
    Task<IdentityResult> CreateAsync(TPermission permission, CancellationToken cancellationToken);

    Task<IdentityResult> UpdateAsync(TPermission permission, CancellationToken cancellationToken);

    Task<IdentityResult> DeleteAsync(TPermission permission, CancellationToken cancellationToken);

    Task<string> GetPermissionIdAsync(TPermission permission, CancellationToken cancellationToken);

    Task<string?> GetPermissionNameAsync(TPermission permission, CancellationToken cancellationToken);

    Task SetPermissionNameAsync(TPermission permission, string? permissionName, CancellationToken cancellationToken);

    Task<string?> GetNormalizedPermissionNameAsync(TPermission permission, CancellationToken cancellationToken);

    Task SetNormalizedPermissionNameAsync(TPermission permission, string? normalizedPermissionName, CancellationToken cancellationToken);

    Task<TPermission?> FindByIdAsync(string permissionId, CancellationToken cancellationToken);

    Task<TPermission?> FindByNameAsync(string normalizedPermissionName, CancellationToken cancellationToken);

    Task<IList<TPermission>> GetAllAsync(CancellationToken cancellationToken);

    Task<IList<TPermission>> FindByNamesAsync(IEnumerable<string> normalizedNames, CancellationToken cancellationToken);
}
