using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Security.RBAC.Core;

public abstract class RbacIdentityDbContext : RbacIdentityDbContext<IdentityUser>
{
    public RbacIdentityDbContext(DbContextOptions options) : base(options) { }

    protected RbacIdentityDbContext() { }
}

public abstract class RbacIdentityDbContext<TUser> : RbacIdentityDbContext<TUser, IdentityPermission>
    where TUser : IdentityUser
{
    public RbacIdentityDbContext(DbContextOptions options) : base(options) { }

    protected RbacIdentityDbContext() { }
}

public abstract class RbacIdentityDbContext<TUser, TPermission> : RbacIdentityDbContext<TUser, IdentityRole, TPermission, string>
    where TUser : IdentityUser
    where TPermission : IdentityPermission
{
    public RbacIdentityDbContext(DbContextOptions options) : base(options) { }

    protected RbacIdentityDbContext() { }
}

public abstract class RbacIdentityDbContext<TUser, TRole, TPermission, TKey> :
    RbacIdentityDbContext<TUser, TRole, TPermission, TKey, IdentityUserClaim<TKey>,
        IdentityUserRole<TKey>, IdentityUserLogin<TKey>, IdentityRoleClaim<TKey>, IdentityUserToken<TKey>>
    where TUser : IdentityUser<TKey>
    where TRole : IdentityRole<TKey>
    where TPermission : IdentityPermission<TKey>
    where TKey : IEquatable<TKey>
{
    public RbacIdentityDbContext(DbContextOptions options) : base(options) { }

    protected RbacIdentityDbContext() { }
}

public abstract class RbacIdentityDbContext<TUser, TRole, TPermission, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken>
    : IdentityDbContext<TUser, TRole, TKey, TUserClaim, TUserRole, TUserLogin, TRoleClaim, TUserToken>
    where TUser : IdentityUser<TKey>
    where TRole : IdentityRole<TKey>
    where TPermission : IdentityPermission<TKey>
    where TKey : IEquatable<TKey>
    where TUserClaim : IdentityUserClaim<TKey>
    where TUserRole : IdentityUserRole<TKey>
    where TUserLogin : IdentityUserLogin<TKey>
    where TRoleClaim : IdentityRoleClaim<TKey>
    where TUserToken : IdentityUserToken<TKey>
{
    protected RbacIdentityDbContext() { }

    protected RbacIdentityDbContext(DbContextOptions options) : base(options) { }

    public virtual DbSet<TPermission> Permissions { get; set; } = default!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        builder.Entity<TPermission>(b =>
        {
            b.HasKey(r => r.Id);
            b.HasIndex(r => r.NormalizedName)
                .HasDatabaseName("PermissionNameIndex")
                .IsUnique();

            b.ToTable("AspNetPermissions");
            b.Property(r => r.ConcurrencyStamp).IsConcurrencyToken();
            b.Property(u => u.Name).HasMaxLength(256);
            b.Property(u => u.NormalizedName).HasMaxLength(256);
        });

        base.OnModelCreating(builder);
    }
}
