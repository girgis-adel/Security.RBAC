namespace Security.RBAC.Core;

public class IdentityPermission : IdentityPermission<string>
{
    public IdentityPermission()
    {
        Id = Guid.NewGuid().ToString();
    }

    public IdentityPermission(string permissionName) : this()
    {
        Name = permissionName;
    }
}

public class IdentityPermission<TKey> where TKey : IEquatable<TKey>
{
    public IdentityPermission() { }

    public IdentityPermission(string permissionName) : this()
    {
        Name = permissionName;
    }

    public virtual TKey Id { get; set; } = default!;

    public virtual string? Name { get; set; }

    public virtual string? NormalizedName { get; set; }

    public virtual string? ConcurrencyStamp { get; set; } = Guid.NewGuid().ToString();

    public override string ToString()
    {
        return Name ?? string.Empty;
    }
}
