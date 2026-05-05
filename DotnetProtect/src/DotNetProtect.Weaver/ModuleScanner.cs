using Mono.Cecil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    private static bool ModuleUsesStringEncryption(ModuleDefinition module)
    {
        foreach (var type in module.GetTypes())
        {
            // [StringEncrypt], [ProtectMembers], or [FullProtect] on a type enables string encryption.
            if (HasAttribute(type, StringEncryptAttr) || HasAttribute(type, ProtectMembersAttr) || HasAttribute(type, FullProtectAttr))
                return true;

            foreach (var method in type.Methods)
            {
                if (HasAttribute(method, StringEncryptAttr))
                    return true;
            }

            foreach (var field in type.Fields)
            {
                if (HasAttribute(field, StringEncryptAttr))
                    return true;
            }
        }

        return false;
    }

    private static bool ModuleUsesObfuscateControlFlow(ModuleDefinition module)
    {
        foreach (var type in module.GetTypes())
        {
            // [ProtectMembers] or [FullProtect] enables CF obfuscation for all methods.
            if (HasAttribute(type, ProtectMembersAttr) || HasAttribute(type, FullProtectAttr))
                return true;

            foreach (var method in type.Methods)
            {
                if (HasAttribute(method, ControlFlowAttr))
                    return true;
            }
        }

        return false;
    }

    private static bool ModuleUsesInjectAntiDebug(ModuleDefinition module)
    {
        if (HasAttribute(module.Assembly, AntiDebugAttr))
            return true;
        foreach (var type in module.GetTypes())
        {
            if (HasAttribute(type, InjectAntiDebugAttr) || HasAttribute(type, AntiDebugAttr) || HasAttribute(type, FullProtectAttr))
                return true;
            foreach (var method in type.Methods)
                if (HasAttribute(method, InjectAntiDebugAttr) || HasAttribute(method, AntiDebugAttr))
                    return true;
        }
        return false;
    }

    private static bool ModuleUsesObfuscateNames(ModuleDefinition module)
    {
        foreach (var type in module.GetTypes())
        {
            if (HasAttribute(type, ObfuscateNamesAttr)) return true;
            foreach (var method in type.Methods)
                if (HasAttribute(method, ObfuscateNamesAttr)) return true;
            foreach (var field in type.Fields)
                if (HasAttribute(field, ObfuscateNamesAttr)) return true;
            foreach (var prop in type.Properties)
                if (HasAttribute(prop, ObfuscateNamesAttr)) return true;
        }
        return false;
    }

    private static bool ModuleUsesVerifyIntegrity(ModuleDefinition module) =>
        module.Assembly.CustomAttributes.Any(a => a.AttributeType.FullName == VerifyIntegrityAttr);

    private static bool ModuleUsesVerifyNativeCoherency(ModuleDefinition module) =>
        module.Assembly.CustomAttributes.Any(a => a.AttributeType.FullName == VerifyNativeCoherencyAttr);

    private static bool ModuleUsesPeProtect(ModuleDefinition module) =>
        module.Assembly.CustomAttributes.Any(a => a.AttributeType.FullName == PeProtectAttr);
}
