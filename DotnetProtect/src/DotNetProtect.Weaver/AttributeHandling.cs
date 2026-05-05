using Mono.Cecil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    private static bool HasAttribute(ICustomAttributeProvider provider, string fullName)
    {
        foreach (var attr in provider.CustomAttributes)
            if (attr.AttributeType.FullName == fullName)
                return true;
        return false;
    }

    private static void StripProtectionAttributes(ModuleDefinition module)
    {
        RemoveProtectionAttributes(module.Assembly);
        foreach (var type in module.GetTypes())
        {
            RemoveProtectionAttributes(type);
            foreach (var m in type.Methods)
                RemoveProtectionAttributes(m);
            foreach (var f in type.Fields)
                RemoveProtectionAttributes(f);
        }
    }

    private static void RemoveProtectionAttributes(ICustomAttributeProvider provider)
    {
        var attrs = provider.CustomAttributes;
        for (var i = attrs.Count - 1; i >= 0; i--)
        {
            var n = attrs[i].AttributeType.FullName;
            if (n == StringEncryptAttr || n == ControlFlowAttr ||
                n == PreserveAttr      || n == ProtectMembersAttr ||
                n == InjectAntiDebugAttr || n == AntiDebugAttr   ||
                n == VerifyIntegrityAttr || n == FullProtectAttr  ||
                n == ObfuscateNamesAttr  || n == PeProtectAttr   ||
                n == VerifyNativeCoherencyAttr)
                attrs.RemoveAt(i);
        }
    }
}
