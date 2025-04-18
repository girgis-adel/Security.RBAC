# Security.RBAC NuGet Package
Reusable RBAC (Role-Based Access Control) package for ASP.NET Core with permission-based authorization.

## Features
- Attribute-based permission checks `[HasPermissions]`.
- Policy provider and handler wired into ASP.NET Core's authorization system.
- Easy integration with ASP.NET Identity.

## Installation
To use Security.RBAC in your ASP.NET Core project, you can install the package via NuGet Package Manager or by using the .NET CLI:

### Using NuGet Package Manager
```bash
Install-Package Security.RBAC
```

### Using .NET CLI
```bash
dotnet add package Security.RBAC
```

### Using PackageReference
Add the following line to your `.csproj` file:
```xml
<PackageReference Include="Security.RBAC" Version="1.0.0" />
```

## Getting Started
1. Add the necessary services in your `Startup.cs` or `Program.cs` file:
```csharp
services.AddRbacAuthorization();
```

2. Use the `[HasPermissions]` attribute on your controllers or actions to enforce permission checks:
```csharp
public class UsersController : Controller
{
	[HasPermissions("Users.Create", "Users.Update")]
	public IActionResult Upsert() => Ok();
}
```  

## Using Permission Store and Manager (Optional)
If you need to manage permissions in a table:
1. Register a custom or default permission type in `Program.cs` or `Startup.cs`:
```csharp
services.AddRbac(typeof(MyCustomPermission)) // or simply use IdentityPermission
	.AddRbacPermissionStore<MyPermissionStore>()
	.AddRbacPermissionValidator<MyPermissionValidator>()
	.AddRbacPermissionManager<MyPermissionManager>();
```
Or use the default built-in setup:
```csharp
services.AddRbac().AddDefaultRbacPermission();
```

2. Implement the following interfaces based on your permission entity:
- `IPermissionStore<TPermission>`
- `IPermissionValidator<TPermission>`
- `PermissionManager<TPermission>`

### Example:
```csharp
public class MyPermissionStore : IPermissionStore<IdentityPermission>
{
	// Implement your logic to fetch permissions from the database
}
```

### Example Permission Entity:
You can use the built-in IdentityPermission or define your own:
```csharp
public class MyCustomPermission : IdentityPermission
{
	// Add additional fields if needed
}
```

## Integration with ASP.NET Identity
**Security.RBAC** is designed to work seamlessly with ASP.NET Identity.
You can store permissions in your Identity database or a separate table and fetch them dynamically.