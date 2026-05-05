using System.Security.Cryptography;
using Mono.Cecil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    private static void CollectRenameCandidates(
        ModuleDefinition module,
        HashSet<MethodDefinition> methods,
        HashSet<FieldDefinition> fields)
    {
        foreach (var type in module.GetTypes())
        {
            var typePreserved = HasAttribute(type, PreserveAttr);

            foreach (var method in type.Methods)
            {
                if (typePreserved || HasAttribute(method, PreserveAttr))
                    continue;
                if (!CanRenameMemberAccessibility(method.Attributes))
                    continue;
                if (method.Name.Contains('.', StringComparison.Ordinal))
                    continue;
                if (IsAssemblyEntryPoint(module, method))
                    continue;
                if (method.IsStatic && string.Equals(method.Name, "Main", StringComparison.Ordinal))
                    continue;

                if (HasAttribute(method, StringEncryptAttr) || HasAttribute(method, ControlFlowAttr))
                    methods.Add(method);
            }

            foreach (var field in type.Fields)
            {
                if (typePreserved || HasAttribute(field, PreserveAttr))
                    continue;
                if (!CanRenameMemberAccessibility(field.Attributes))
                    continue;
                if (field.HasConstant)
                    continue;
                if (field.FieldType.FullName != "System.String")
                    continue;
                if (HasAttribute(field, StringEncryptAttr))
                    fields.Add(field);
            }
        }
    }

    private static bool CanRenameMemberAccessibility(FieldAttributes a)
    {
        var access = a & FieldAttributes.FieldAccessMask;
        return access is FieldAttributes.Private or FieldAttributes.Assembly or FieldAttributes.FamANDAssem;
    }

    private static bool CanRenameMemberAccessibility(MethodAttributes a)
    {
        var access = a & MethodAttributes.MemberAccessMask;
        return access is MethodAttributes.Private or MethodAttributes.Assembly or MethodAttributes.FamANDAssem;
    }

    private static bool IsAssemblyEntryPoint(ModuleDefinition module, MethodDefinition method)
    {
        var ep = module.EntryPoint;
        return ep is not null && ep.Resolve() == method;
    }

    private static bool ApplyPrivateMarkedRenames(
        ModuleDefinition module,
        HashSet<MethodDefinition> methods,
        HashSet<FieldDefinition> fields)
    {
        var any = false;
        foreach (var method in methods)
        {
            if (method.Module != module) continue;
            var decl = method.DeclaringType;
            if (decl is null) continue;

            method.Name = AllocateUniqueName(decl.Methods, m => m.Name, "__m");
            any = true;
        }

        foreach (var field in fields)
        {
            if (field.Module != module) continue;
            var decl = field.DeclaringType;
            if (decl is null) continue;

            field.Name = AllocateUniqueName(decl.Fields, f => f.Name, "__f");
            any = true;
        }

        return any;
    }

    private static bool ApplyFullMetadataMangling(ModuleDefinition module)
    {
        var any = false;
        var obfNs = "__dnp_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));

        var typeWorklist = module.GetTypes()
            .Where(t => IsCandidateForFullTypeMangle(t) && !HasAttribute(t, PreserveAttr))
            .OrderByDescending(NestedTypeDepth)
            .ToList();

        foreach (var type in typeWorklist)
        {
            if (!ShouldRenameTypeIdentityForFull(type))
                continue;

            if (!type.IsNested && type.IsNotPublic)
                type.Namespace = obfNs;

            type.Name = "t_" + Guid.NewGuid().ToString("N")[..14];
            any = true;
        }

        foreach (var type in module.GetTypes())
        {
            if (IsExcludedFromMemberMangling(type))
                continue;

            var typePreserved = HasAttribute(type, PreserveAttr);

            foreach (var method in type.Methods)
            {
                if (typePreserved || HasAttribute(method, PreserveAttr))
                    continue;
                if (!ShouldRenameMethodForFullMetadata(module, method))
                    continue;

                method.Name = AllocateUniqueName(type.Methods, m => m.Name, "__m");
                any = true;
            }

            foreach (var field in type.Fields)
            {
                if (typePreserved || HasAttribute(field, PreserveAttr))
                    continue;
                if (!ShouldRenameFieldForFullMetadata(field))
                    continue;

                field.Name = AllocateUniqueName(type.Fields, f => f.Name, "__f");
                any = true;
            }

            if (!typePreserved && type.HasProperties)
            {
                var methodNames = new HashSet<string>(type.Methods.Select(m => m.Name), StringComparer.Ordinal);
                var propNames   = new HashSet<string>(type.Properties.Select(p => p.Name), StringComparer.Ordinal);
                foreach (var prop in type.Properties)
                {
                    if (TryRenameProperty(prop, methodNames, propNames))
                        any = true;
                }
            }
        }

        return any;
    }

    private static bool IsCandidateForFullTypeMangle(TypeDefinition type)
    {
        if (type.FullName == "<Module>") return false;
        if (type.Name.StartsWith("<", StringComparison.Ordinal)) return false;
        if (string.Equals(type.Namespace, "DotNetProtect", StringComparison.Ordinal) &&
            type.Name.StartsWith("Generated", StringComparison.Ordinal))
            return false;
        return !IsBlockedCompilerInfrastructureType(type);
    }

    private static bool ShouldRenameTypeIdentityForFull(TypeDefinition type)
    {
        if (!type.IsNested)
            return type.IsNotPublic;

        var vis = type.Attributes & TypeAttributes.VisibilityMask;
        return vis is TypeAttributes.NestedPrivate or TypeAttributes.NestedAssembly or TypeAttributes.NestedFamANDAssem;
    }

    private static int NestedTypeDepth(TypeDefinition type)
    {
        var depth = 0;
        for (var t = type; t.IsNested; t = t.DeclaringType!)
            depth++;
        return depth;
    }

    private static bool IsBlockedCompilerInfrastructureType(TypeDefinition type)
    {
        if (type.Name.Contains("PrivateImplementationDetails", StringComparison.Ordinal))
            return true;
        return type.CustomAttributes.Any(a => a.AttributeType.Name == "CompilerGeneratedAttribute");
    }

    private static bool IsExcludedFromMemberMangling(TypeDefinition type)
    {
        if (type.FullName == "<Module>" || type.Name.StartsWith("<", StringComparison.Ordinal))
            return true;
        if (string.Equals(type.Namespace, "DotNetProtect", StringComparison.Ordinal) &&
            type.Name.StartsWith("Generated", StringComparison.Ordinal))
            return true;
        return IsBlockedCompilerInfrastructureType(type);
    }

    private static bool ShouldRenameMethodForFullMetadata(ModuleDefinition module, MethodDefinition method)
    {
        if (!CanRenameMemberAccessibility(method.Attributes)) return false;
        if (method.IsSpecialName) return false;
        if (method.Name.Contains('.', StringComparison.Ordinal)) return false;
        if (IsAssemblyEntryPoint(module, method)) return false;
        if (method.IsStatic && string.Equals(method.Name, "Main", StringComparison.Ordinal)) return false;
        return true;
    }

    private static bool ShouldRenameFieldForFullMetadata(FieldDefinition field)
    {
        if (!CanRenameMemberAccessibility(field.Attributes)) return false;
        if (field.IsRuntimeSpecialName) return false;
        if (field.HasConstant) return false;

        // Allow auto-property backing fields ('<PropName>k__BackingField') to be renamed —
        // the property name itself is otherwise leaked in metadata. All other compiler-mangled
        // names ('<X>5__1' state machine fields, etc.) are kept intact to avoid breaking lifted closures.
        if (field.Name.StartsWith("<", StringComparison.Ordinal))
            return field.Name.EndsWith(">k__BackingField", StringComparison.Ordinal);

        return true;
    }

    /// <summary>
    /// Renames a property along with its accessors. The accessor names must keep their
    /// <c>get_</c> / <c>set_</c> prefix for CLR property semantics, so we generate one random
    /// suffix and stitch it onto each.
    /// </summary>
    private static bool TryRenameProperty(PropertyDefinition prop, HashSet<string> typeMethodNames, HashSet<string> typePropNames)
    {
        if (HasAttribute(prop, PreserveAttr)) return false;
        if (prop.IsRuntimeSpecialName) return false;

        // Skip overrides / interface implementations — renaming would break the contract.
        if (!CanRenameAccessor(prop.GetMethod)) return false;
        if (!CanRenameAccessor(prop.SetMethod)) return false;
        foreach (var other in prop.OtherMethods)
            if (!CanRenameAccessor(other)) return false;

        string suffix;
        do
        {
            suffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        }
        while (!typePropNames.Add("__p_" + suffix)
               || (prop.GetMethod is not null && !typeMethodNames.Add("get___p_" + suffix))
               || (prop.SetMethod is not null && !typeMethodNames.Add("set___p_" + suffix)));

        prop.Name = "__p_" + suffix;
        if (prop.GetMethod is not null) prop.GetMethod.Name = "get___p_" + suffix;
        if (prop.SetMethod is not null) prop.SetMethod.Name = "set___p_" + suffix;
        return true;
    }

    private static bool CanRenameAccessor(MethodDefinition? accessor)
    {
        if (accessor is null) return true; // missing accessor is OK (read-only / write-only).
        if (HasAttribute(accessor, PreserveAttr)) return false;
        if (!CanRenameMemberAccessibility(accessor.Attributes)) return false;
        if (accessor.IsVirtual || accessor.IsAbstract) return false;
        // Explicit interface implementations have '.' in the name.
        if (accessor.Name.Contains('.', StringComparison.Ordinal)) return false;
        return true;
    }

    private static string AllocateUniqueName<T>(IEnumerable<T> siblings, Func<T, string> nameOf, string prefix)
    {
        var used = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in siblings)
            used.Add(nameOf(s));

        while (true)
        {
            var candidate = $"{prefix}_{Convert.ToHexString(RandomNumberGenerator.GetBytes(8))}";
            if (used.Add(candidate))
                return candidate;
        }
    }

    private static void CollectAttributeNameCandidates(
        ModuleDefinition module,
        HashSet<TypeDefinition> types,
        HashSet<MethodDefinition> methods,
        HashSet<FieldDefinition> fields)
    {
        foreach (var type in module.GetTypes())
        {
            if (type.FullName == "<Module>") continue;
            if (type.Name.StartsWith("<", StringComparison.Ordinal)) continue;
            if (IsBlockedCompilerInfrastructureType(type)) continue;

            var typePreserved       = HasAttribute(type, PreserveAttr);
            var typeObfuscateNames  = !typePreserved && HasAttribute(type, ObfuscateNamesAttr);

            if (typeObfuscateNames && ShouldRenameTypeIdentityForFull(type))
                types.Add(type);

            foreach (var method in type.Methods)
            {
                if (typePreserved || HasAttribute(method, PreserveAttr)) continue;
                if (typeObfuscateNames || HasAttribute(method, ObfuscateNamesAttr))
                {
                    if (ShouldRenameMethodForFullMetadata(module, method))
                        methods.Add(method);
                }
            }

            foreach (var field in type.Fields)
            {
                if (typePreserved || HasAttribute(field, PreserveAttr)) continue;
                if (typeObfuscateNames || HasAttribute(field, ObfuscateNamesAttr))
                {
                    if (ShouldRenameFieldForFullMetadata(field))
                        fields.Add(field);
                }
            }
        }
    }

    private static bool ApplyAttributeNameRenames(
        ModuleDefinition module,
        HashSet<TypeDefinition> types,
        HashSet<MethodDefinition> methods,
        HashSet<FieldDefinition> fields)
    {
        var any = false;
        var obfNs = "__dnp_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8));

        foreach (var type in types)
        {
            if (!type.IsNested && type.IsNotPublic)
                type.Namespace = obfNs;
            type.Name = "t_" + Guid.NewGuid().ToString("N")[..14];
            any = true;
        }

        foreach (var method in methods)
        {
            if (method.Module != module) continue;
            var decl = method.DeclaringType;
            if (decl is null) continue;
            method.Name = AllocateUniqueName(decl.Methods, m => m.Name, "__m");
            any = true;
        }

        foreach (var field in fields)
        {
            if (field.Module != module) continue;
            var decl = field.DeclaringType;
            if (decl is null) continue;
            field.Name = AllocateUniqueName(decl.Fields, f => f.Name, "__f");
            any = true;
        }

        // Properties: rename those explicitly tagged or inside a tagged type.
        foreach (var type in module.GetTypes())
        {
            if (IsExcludedFromMemberMangling(type)) continue;
            if (HasAttribute(type, PreserveAttr)) continue;
            if (!type.HasProperties) continue;

            var typeObfuscateNames = HasAttribute(type, ObfuscateNamesAttr);
            var methodNames = new HashSet<string>(type.Methods.Select(m => m.Name), StringComparer.Ordinal);
            var propNames   = new HashSet<string>(type.Properties.Select(p => p.Name), StringComparer.Ordinal);

            foreach (var prop in type.Properties)
            {
                if (!typeObfuscateNames && !HasAttribute(prop, ObfuscateNamesAttr)) continue;
                if (TryRenameProperty(prop, methodNames, propNames))
                    any = true;
            }
        }

        return any;
    }
}
