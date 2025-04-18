using Microsoft.Extensions.DependencyInjection;
using Security.RBAC.Core;
using Security.RBAC.Stores;
using System.Diagnostics.CodeAnalysis;

namespace Security.RBAC.EntityFrameworkCore;

public class RbacBuilder
{
    public RbacBuilder(
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type permission,
        IServiceCollection services)
    {
        if (permission.IsValueType)
        {
            throw new ArgumentException("Permission type can't be a value type.", nameof(permission));
        }

        PermissionType = permission;
        Services = services;
    }

    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
    public Type PermissionType { get; }

    public IServiceCollection Services { get; }

    private RbacBuilder AddScoped(Type serviceType, 
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type concreteType)
    {
        Services.AddScoped(serviceType, concreteType);
        return this;
    }

    [UnconditionalSuppressMessage("AOT", "IL3050", Justification = "MakeGenericType is safe because PermissionType is a reference type.")]
    public virtual RbacBuilder AddRbacPermissionValidator<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TValidator
        >() where TValidator : class
    {
        return AddScoped(typeof(IPermissionValidator<>).MakeGenericType(PermissionType), typeof(TValidator));
    }

    [UnconditionalSuppressMessage("AOT", "IL3050", Justification = "MakeGenericType is safe because PermissionType is a reference type.")]
    public virtual RbacBuilder AddRbacPermissionStore<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] TStore
        >() where TStore : class
    {
        return AddScoped(typeof(IPermissionStore<>).MakeGenericType(PermissionType), typeof(TStore));
    }

    [UnconditionalSuppressMessage("AOT", "IL3050", Justification = "MakeGenericType is safe because PermissionType is a reference type.")]
    public virtual RbacBuilder AddRbacPermissionManager<
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]TManager
        >() where TManager : class
    {
        var managerType = typeof(PermissionManager<>).MakeGenericType(PermissionType);
        var customType = typeof(TManager);

        if (!managerType.IsAssignableFrom(customType))
        {
            throw new InvalidOperationException(
                $"Type {customType.Name} must implement {managerType.Name}.");
        }

        if (managerType != customType)
        {
            Services.AddScoped(customType, services => services.GetRequiredService(managerType));
        }

        return AddScoped(managerType, customType);
    }

    public virtual RbacBuilder AddDefaultRbacPermission()
    {
        AddRbacPermissionStore<PermissionStore<IdentityPermission>>()
            .AddRbacPermissionValidator<PermissionValidator<IdentityPermission>>()
            .AddRbacPermissionManager<PermissionManager<IdentityPermission>>();
        return this;
    }
}
