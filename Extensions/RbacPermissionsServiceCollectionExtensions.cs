using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Security.RBAC.Authorization;
using Security.RBAC.Core;
using Security.RBAC.EntityFrameworkCore;
using System.Diagnostics.CodeAnalysis;

namespace Security.RBAC.Extensions;

public static class RbacPermissionsServiceCollectionExtensions
{
    public static IServiceCollection AddRbacAuthorization(this IServiceCollection services)
    {
        services.AddSingleton<IAuthorizationPolicyProvider, RbacPermissionPolicyProvider>();
        services.AddScoped<IAuthorizationHandler, HasRbacPermissionsHandler>();
        return services;
    }

    public static RbacBuilder AddRbac(this IServiceCollection services,
        [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)] Type permission)
    {
        return new RbacBuilder(permission, services);
    }

    public static RbacBuilder AddRbac(this IServiceCollection services)
    {
        return services.AddRbac(typeof(IdentityPermission));
    }
}
