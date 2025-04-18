using Microsoft.AspNetCore.Authorization;
using Security.RBAC.Constants;

namespace Security.RBAC.Attributes;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true, Inherited = true)]
public class HasPermissionsAttribute(params string[] permissions) 
    : AuthorizeAttribute($"{RbacPermissionsConstants.PermissionsPolicyPrefix}:{string.Join(",", permissions)}");
