using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using System.Diagnostics.CodeAnalysis;

namespace Security.RBAC.Stores;

public class PermissionManager<TPermission> : IDisposable
    where TPermission : class
{
    private bool _disposed;

    protected virtual CancellationToken CancellationToken => CancellationToken.None;

    public PermissionManager(IPermissionStore<TPermission> store,
        IEnumerable<IPermissionValidator<TPermission>> permissionValidators,
        ILogger<PermissionManager<TPermission>> logger)
    {
        ArgumentNullException.ThrowIfNull(store);
        Store = store;
        Logger = logger;

        if (permissionValidators != null)
        {
            foreach (var v in permissionValidators)
            {
                PermissionValidators.Add(v);
            }
        }
    }

    protected IPermissionStore<TPermission> Store { get; private set; }

    public virtual ILogger Logger { get; set; }

    public IList<IPermissionValidator<TPermission>> PermissionValidators { get; } = new List<IPermissionValidator<TPermission>>();

    public virtual IQueryable<TPermission> Permissions
    {
        get
        {
            return Store is not IQueryablePermissionStore<TPermission> queryableStore
                ? throw new NotSupportedException("Store does not implement `IQueryablePermissionStore<TPermission>`.")
                : queryableStore.Permissions;
        }
    }

    public virtual bool SupportsQueryablePermissions
    {
        get
        {
            ThrowIfDisposed();
            return Store is IQueryablePermissionStore<TPermission>;
        }
    }

    public virtual async Task<IdentityResult> CreateAsync(TPermission permission)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permission);
        var result = await ValidatePermissionAsync(permission).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return result;
        }
        await UpdateNormalizedPermissionNameAsync(permission).ConfigureAwait(false);
        result = await Store.CreateAsync(permission, CancellationToken).ConfigureAwait(false);
        return result;
    }

    public virtual async Task UpdateNormalizedPermissionNameAsync(TPermission permission)
    {
        var name = await GetPermissionNameAsync(permission).ConfigureAwait(false);
        await Store.SetNormalizedPermissionNameAsync(permission, NormalizeKey(name), CancellationToken).ConfigureAwait(false);
    }

    public virtual Task<IdentityResult> UpdateAsync(TPermission permission)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permission);
        return UpdatePermissionAsync(permission);
    }

    public virtual Task<IdentityResult> DeleteAsync(TPermission permission)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permission);
        return Store.DeleteAsync(permission, CancellationToken);
    }

    public virtual async Task<bool> PermissionExistsAsync(string permissionName)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permissionName);
        return await FindByNameAsync(permissionName).ConfigureAwait(false) != null;
    }

    [return: NotNullIfNotNull(nameof(key))]
    public virtual string? NormalizeKey(string? key)
    {
        return key?.Normalize().ToUpperInvariant();
    }

    public virtual Task<TPermission?> FindByIdAsync(string permissionId)
    {
        ThrowIfDisposed();
        return Store.FindByIdAsync(permissionId, CancellationToken);
    }

    public virtual Task<string?> GetPermissionNameAsync(TPermission permission)
    {
        ThrowIfDisposed();
        return Store.GetPermissionNameAsync(permission, CancellationToken);
    }

    public virtual async Task<IdentityResult> SetPermissionNameAsync(TPermission permission, string? name)
    {
        ThrowIfDisposed();
        await Store.SetPermissionNameAsync(permission, name, CancellationToken).ConfigureAwait(false);
        await UpdateNormalizedPermissionNameAsync(permission).ConfigureAwait(false);
        return IdentityResult.Success;
    }

    public virtual Task<string> GetPermissionIdAsync(TPermission permission)
    {
        ThrowIfDisposed();
        return Store.GetPermissionIdAsync(permission, CancellationToken);
    }

    public virtual Task<TPermission?> FindByNameAsync(string permissionName)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permissionName);
        return Store.FindByNameAsync(NormalizeKey(permissionName), CancellationToken);
    }

    public virtual async Task<IList<TPermission>> GetAllAsync()
    {
        ThrowIfDisposed();
        return await Store.GetAllAsync(CancellationToken);
    }

    public virtual async Task<IList<TPermission>> FindByNamesAsync(IEnumerable<string> names)
    {
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(names);
        var normalizedNames = names.Select(NormalizeKey).ToList();
        return await Store.FindByNamesAsync(normalizedNames!, CancellationToken);
    }

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    protected virtual void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            Store.Dispose();
        }
        _disposed = true;
    }

    protected virtual async Task<IdentityResult> ValidatePermissionAsync(TPermission permission)
    {
        List<IdentityError>? errors = null;
        foreach (var v in PermissionValidators)
        {
            var result = await v.ValidateAsync(this, permission).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                errors ??= [];
                errors.AddRange(result.Errors);
            }
        }
        if (errors?.Count > 0)
        {
            if (Logger.IsEnabled(LogLevel.Warning))
            {
                Logger.LogWarning("Permission {permissionId} validation failed: {errors}.", await GetPermissionIdAsync(permission).ConfigureAwait(false), string.Join(";", errors.Select(e => e.Code)));
            }
            return IdentityResult.Failed([.. errors]);
        }
        return IdentityResult.Success;
    }

    protected virtual async Task<IdentityResult> UpdatePermissionAsync(TPermission permission)
    {
        var result = await ValidatePermissionAsync(permission).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return result;
        }
        await UpdateNormalizedPermissionNameAsync(permission).ConfigureAwait(false);
        return await Store.UpdateAsync(permission, CancellationToken).ConfigureAwait(false);
    }

    protected void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
