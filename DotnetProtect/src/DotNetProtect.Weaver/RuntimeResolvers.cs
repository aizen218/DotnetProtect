using Mono.Cecil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    private static MethodReference? FindDecryptMethod(ModuleDefinition module)
    {
        foreach (var reference in module.AssemblyReferences)
        {
            if (!string.Equals(reference.Name, "DotNetProtect", StringComparison.Ordinal))
                continue;

            try
            {
                var asm = module.AssemblyResolver.Resolve(reference);
                var type = asm.MainModule.GetType("DotNetProtect.Runtime.StringDecrypt");
                var method = type?.Methods.FirstOrDefault(m => m.Name == "FromAes256CbcUtf8" && m.Parameters.Count == 2);
                if (method is not null)
                    return module.ImportReference(method);
            }
            catch (FileNotFoundException) { }
        }

        var localType = module.GetType("DotNetProtect.Runtime.StringDecrypt");
        var localMethod = localType?.Methods.FirstOrDefault(m => m.Name == "FromAes256CbcUtf8" && m.Parameters.Count == 2);
        return localMethod is null ? null : module.ImportReference(localMethod);
    }

    private static ConstantDecrypters? FindConstantDecrypters(ModuleDefinition module)
    {
        TypeDefinition? td = null;

        foreach (var reference in module.AssemblyReferences)
        {
            if (!string.Equals(reference.Name, "DotNetProtect", StringComparison.Ordinal))
                continue;

            try
            {
                var asm = module.AssemblyResolver.Resolve(reference);
                td = asm.MainModule.GetType("DotNetProtect.Runtime.ConstantDecrypt");
                if (td is not null)
                    break;
            }
            catch (FileNotFoundException) { }
        }

        td ??= module.GetType("DotNetProtect.Runtime.ConstantDecrypt");
        if (td is null)
            return null;

        MethodReference? Import(string name)
        {
            var md = td!.Methods.FirstOrDefault(m => m.Name == name && m.Parameters.Count == 2);
            return md is null ? null : module.ImportReference(md);
        }

        var i32 = Import("FromXorInt32");
        var i64 = Import("FromXorInt64");
        var f32 = Import("FromXorSingle");
        var f64 = Import("FromXorDouble");
        if (i32 is null || i64 is null || f32 is null || f64 is null)
            return null;

        return new ConstantDecrypters(i32, i64, f32, f64);
    }

    private static AntiDebugInjector? FindAntiDebugInjector(ModuleDefinition module)
    {
        MethodReference? likelyRef = null;

        foreach (var reference in module.AssemblyReferences)
        {
            if (!string.Equals(reference.Name, "DotNetProtect", StringComparison.Ordinal))
                continue;

            try
            {
                var asm    = module.AssemblyResolver.Resolve(reference);
                var type   = asm.MainModule.GetType("DotNetProtect.Runtime.AntiDebug");
                var method = type?.Methods.FirstOrDefault(m => m.Name == "LikelyUnderDebugger" && m.Parameters.Count == 0);
                if (method is not null)
                {
                    likelyRef = module.ImportReference(method);
                    break;
                }
            }
            catch (FileNotFoundException) { }
        }

        if (likelyRef is null)
        {
            var localType   = module.GetType("DotNetProtect.Runtime.AntiDebug");
            var localMethod = localType?.Methods.FirstOrDefault(m => m.Name == "LikelyUnderDebugger" && m.Parameters.Count == 0);
            if (localMethod is null) return null;
            likelyRef = module.ImportReference(localMethod);
        }

        // System.Environment.Exit(int32) — resolved via core library.
        var coreLib = module.TypeSystem.CoreLibrary;
        var envRef  = new TypeReference("System", "Environment", module, coreLib);
        var exitRef = new MethodReference("Exit", module.TypeSystem.Void, envRef);
        exitRef.Parameters.Add(new ParameterDefinition(module.TypeSystem.Int32));
        var importedExit = module.ImportReference(exitRef);

        return new AntiDebugInjector(likelyRef, importedExit);
    }

    private static MethodReference? FindIntegrityVerifyMethod(ModuleDefinition module)
    {
        foreach (var reference in module.AssemblyReferences)
        {
            if (!string.Equals(reference.Name, "DotNetProtect", StringComparison.Ordinal))
                continue;

            try
            {
                var asm    = module.AssemblyResolver.Resolve(reference);
                var type   = asm.MainModule.GetType("DotNetProtect.Runtime.Integrity");
                var method = type?.Methods.FirstOrDefault(m =>
                    m.Name == "VerifyTableOrFail" &&
                    m.Parameters.Count == 4 &&
                    m.ReturnType.MetadataType == MetadataType.Void);
                if (method is not null)
                    return module.ImportReference(method);
            }
            catch (FileNotFoundException) { }
        }

        var localType   = module.GetType("DotNetProtect.Runtime.Integrity");
        var localMethod = localType?.Methods.FirstOrDefault(m =>
            m.Name == "VerifyTableOrFail" &&
            m.Parameters.Count == 4 &&
            m.ReturnType.MetadataType == MetadataType.Void);
        return localMethod is null ? null : module.ImportReference(localMethod);
    }

    private static MethodReference? FindNativeTextIntegrityVerifyMethod(ModuleDefinition module)
    {
        foreach (var reference in module.AssemblyReferences)
        {
            if (!string.Equals(reference.Name, "DotNetProtect", StringComparison.Ordinal))
                continue;

            try
            {
                var asm = module.AssemblyResolver.Resolve(reference);
                var type = asm.MainModule.GetType("DotNetProtect.Runtime.NativeTextIntegrity");
                var method = type?.Methods.FirstOrDefault(m =>
                    m.Name == "VerifyProcessImageMatchesOnDiskOrFail" &&
                    m.Parameters.Count == 1 &&
                    m.Parameters[0].ParameterType.MetadataType == MetadataType.Int32 &&
                    m.ReturnType.MetadataType == MetadataType.Void);
                if (method is not null)
                    return module.ImportReference(method);
            }
            catch (FileNotFoundException) { }
        }

        var localType = module.GetType("DotNetProtect.Runtime.NativeTextIntegrity");
        var localMethod = localType?.Methods.FirstOrDefault(m =>
            m.Name == "VerifyProcessImageMatchesOnDiskOrFail" &&
            m.Parameters.Count == 1 &&
            m.Parameters[0].ParameterType.MetadataType == MetadataType.Int32 &&
            m.ReturnType.MetadataType == MetadataType.Void);
        return localMethod is null ? null : module.ImportReference(localMethod);
    }

    private static MethodReference? FindCombineKey5Method(ModuleDefinition module)
    {
        foreach (var reference in module.AssemblyReferences)
        {
            if (!string.Equals(reference.Name, "DotNetProtect", StringComparison.Ordinal))
                continue;

            try
            {
                var asm    = module.AssemblyResolver.Resolve(reference);
                var type   = asm.MainModule.GetType("DotNetProtect.Runtime.StringDecrypt");
                var method = type?.Methods.FirstOrDefault(m => m.Name == "CombineKey5" && m.Parameters.Count == 5);
                if (method is not null)
                    return module.ImportReference(method);
            }
            catch (FileNotFoundException) { }
        }

        var localType = module.GetType("DotNetProtect.Runtime.StringDecrypt");
        var localMethod = localType?.Methods.FirstOrDefault(m => m.Name == "CombineKey5" && m.Parameters.Count == 5);
        return localMethod is null ? null : module.ImportReference(localMethod);
    }

    private static MethodReference ImportModuleInitializerCtor(ModuleDefinition module)
    {
        var attrType = new TypeReference(
            "System.Runtime.CompilerServices",
            "ModuleInitializerAttribute",
            module,
            module.TypeSystem.CoreLibrary,
            false);
        var ctor = new MethodReference(".ctor", module.TypeSystem.Void, attrType) { HasThis = true };
        return module.ImportReference(ctor);
    }

    private static MethodReference ImportFuncInt32ByteArrayCtor(ModuleDefinition module)
    {
        var core    = module.TypeSystem.CoreLibrary;
        var byteArr = new ArrayType(module.TypeSystem.Byte);
        var func2   = new TypeReference("System", "Func`2", module, core, false);
        var funcInst = new GenericInstanceType(func2);
        funcInst.GenericArguments.Add(module.TypeSystem.Int32);
        funcInst.GenericArguments.Add(byteArr);

        var intPtr = new TypeReference("System", "IntPtr", module, core, true);
        var ctor = new MethodReference(".ctor", module.TypeSystem.Void, funcInst) { HasThis = true };
        ctor.Parameters.Add(new ParameterDefinition(module.TypeSystem.Object));
        ctor.Parameters.Add(new ParameterDefinition(intPtr));
        return module.ImportReference(ctor);
    }

    private static MethodReference ImportEnvironmentFailFastString(ModuleDefinition module)
    {
        var env = new TypeReference("System", "Environment", module, module.TypeSystem.CoreLibrary, false);
        var m = new MethodReference("FailFast", module.TypeSystem.Void, env) { HasThis = false };
        m.Parameters.Add(new ParameterDefinition(module.TypeSystem.String));
        return module.ImportReference(m);
    }
}
