namespace Security.RBAC.Stores;

public interface IQueryablePermissionStore<TPermission> : IPermissionStore<TPermission>
    where TPermission : class
{
    IQueryable<TPermission> Permissions { get; }
}
