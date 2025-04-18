using Microsoft.EntityFrameworkCore;

namespace Security.RBAC.Core;

public class RbacDbContext : RbacDbContext<IdentityPermission>
{
    public RbacDbContext(DbContextOptions options) : base(options) { }

    protected RbacDbContext() { }
}

public class RbacDbContext<TPermission> : RbacDbContext<TPermission, string>
    where TPermission : IdentityPermission<string>
{
    public RbacDbContext(DbContextOptions options) : base(options) { }

    protected RbacDbContext() { }
}

public class RbacDbContext<TPermission, TKey> : DbContext
    where TPermission : IdentityPermission<TKey>
    where TKey : IEquatable<TKey>
{
    public RbacDbContext(DbContextOptions options) : base(options) { }

    protected RbacDbContext() { }

    public virtual DbSet<TPermission> Permissions { get; set; } = default!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        builder.Entity<TPermission>(b =>
        {
            b.HasKey(r => r.Id);
            b.HasIndex(r => r.NormalizedName)
                .HasDatabaseName("PermissionNameIndex")
                .IsUnique();

            b.ToTable("Permissions");
            b.Property(r => r.ConcurrencyStamp).IsConcurrencyToken();
            b.Property(u => u.Name).HasMaxLength(256);
            b.Property(u => u.NormalizedName).HasMaxLength(256);
        });

        base.OnModelCreating(builder);
    }
}
