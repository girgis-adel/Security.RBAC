using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Security.RBAC.Core;
using System.ComponentModel;

namespace Security.RBAC.Stores;

public class PermissionStore<TPermission>(DbContext context) : PermissionStore<TPermission, DbContext>(context)
    where TPermission : IdentityPermission<string>;

public class PermissionStore<TPermission, TContext>(TContext context) : PermissionStore<TPermission, TContext, string>(context)
    where TPermission : IdentityPermission<string>
    where TContext : DbContext;

public class PermissionStore<TPermission, TContext, TKey>(TContext context) : IQueryablePermissionStore<TPermission>
    where TPermission : IdentityPermission<TKey>
    where TKey : IEquatable<TKey>
    where TContext : DbContext
{
    private bool _disposed;

    public virtual TContext Context { get; private set; } = context;

    public bool AutoSaveChanges { get; set; } = true;

    protected virtual async Task SaveChanges(CancellationToken cancellationToken = default)
    {
        if (AutoSaveChanges)
        {
            await Context.SaveChangesAsync(cancellationToken);
        }
    }

    public virtual async Task<IdentityResult> CreateAsync(TPermission permission, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permission);
        Context.Add(permission);
        await SaveChanges(cancellationToken);
        return IdentityResult.Success;
    }

    public virtual async Task<IdentityResult> UpdateAsync(TPermission permission, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permission);
        Context.Attach(permission);
        permission.ConcurrencyStamp = Guid.NewGuid().ToString();
        Context.Update(permission);
        try
        {
            await SaveChanges(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            return IdentityResult.Failed(new IdentityError
            {
                Code = "ConcurrencyFailure",
                Description = "Optimistic concurrency failure, object has been modified."
            });
        }
        return IdentityResult.Success;
    }

    public virtual async Task<IdentityResult> DeleteAsync(TPermission permission, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permission);
        Context.Remove(permission);
        try
        {
            await SaveChanges(cancellationToken);
        }
        catch (DbUpdateConcurrencyException)
        {
            return IdentityResult.Failed(new IdentityError
            {
                Code = "ConcurrencyFailure",
                Description = "Optimistic concurrency failure, object has been modified."
            });
        }
        return IdentityResult.Success;
    }

    public virtual Task<string> GetPermissionIdAsync(TPermission permission, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permission);
        return Task.FromResult(ConvertIdToString(permission.Id)!);
    }

    public virtual Task<string?> GetPermissionNameAsync(TPermission permission, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permission);
        return Task.FromResult(permission.Name);
    }

    public virtual Task SetPermissionNameAsync(TPermission permission, string? permissionName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permission);
        permission.Name = permissionName;
        return Task.CompletedTask;
    }

    public virtual TKey? ConvertIdFromString(string id)
    {
        if (id == null)
        {
            return default;
        }
        return (TKey?)TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
    }

    public virtual string? ConvertIdToString(TKey id)
    {
        if (id.Equals(default))
        {
            return null;
        }
        return id.ToString();
    }

    public virtual Task<TPermission?> FindByIdAsync(string permissionId, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        var id = ConvertIdFromString(permissionId);
        return Permissions.FirstOrDefaultAsync(u => u.Id.Equals(id), cancellationToken);
    }

    public virtual Task<TPermission?> FindByNameAsync(string normalizedPermissionName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return Permissions.FirstOrDefaultAsync(r => r.NormalizedName == normalizedPermissionName, cancellationToken);
    }

    public virtual Task<string?> GetNormalizedPermissionNameAsync(TPermission permission, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permission);
        return Task.FromResult(permission.NormalizedName);
    }

    public virtual Task SetNormalizedPermissionNameAsync(TPermission permission, string? normalizedPermissionName, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(permission);
        permission.NormalizedName = normalizedPermissionName;
        return Task.CompletedTask;
    }

    public virtual async Task<IList<TPermission>> GetAllAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        return await Permissions.ToListAsync(cancellationToken);
    }

    public virtual async Task<IList<TPermission>> FindByNamesAsync(IEnumerable<string> normalizedNames, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ThrowIfDisposed();
        ArgumentNullException.ThrowIfNull(normalizedNames);
        if (!normalizedNames.Any()) return Array.Empty<TPermission>();
        var permissions = await Permissions
            .Where(r => normalizedNames.Contains(r.NormalizedName))
            .ToListAsync(cancellationToken);
        return permissions;
    }

    protected void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }

    public void Dispose() => _disposed = true;

    public virtual IQueryable<TPermission> Permissions => Context.Set<TPermission>();
}
