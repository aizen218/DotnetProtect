using System.Security.Cryptography;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    private static bool ApplyIntegrityManifest(ModuleDefinition module, TypeDefinition blobHolder, MethodReference verifyRef)
    {
        if (blobHolder.Methods.Any(m => m.Name == IntegrityModuleInitName))
            return false;

        var dataFields = blobHolder.Fields
            .Where(f => f.HasFieldRVA && f.InitialValue is { Length: > 0 } && f.Name.StartsWith("__data_", StringComparison.Ordinal))
            .OrderBy(f => f.Name, StringComparer.Ordinal)
            .ToList();

        var chunkGetters = new List<MethodDefinition>(dataFields.Count);
        foreach (var field in dataFields)
        {
            var getter = FindBlobGetterForField(blobHolder, field);
            if (getter is null)
            {
                throw new InvalidOperationException(
                    $"DotNetProtect: [VerifyIntegrity] could not resolve blob getter for field '{field.Name}'.");
            }

            chunkGetters.Add(getter);
        }

        long totalLen = 0;
        foreach (var f in dataFields)
            totalLen += f.InitialValue!.Length;
        if (totalLen > int.MaxValue)
            throw new InvalidOperationException("DotNetProtect: integrity manifest exceeds 2 GiB.");

        var table = new byte[(int)totalLen];
        var off   = 0;
        foreach (var f in dataFields)
        {
            var iv = f.InitialValue!;
            Buffer.BlockCopy(iv, 0, table, off, iv.Length);
            off += iv.Length;
        }

        var seed     = RandomNumberGenerator.GetBytes(16);
        var combined = new byte[16 + table.Length];
        Buffer.BlockCopy(seed, 0, combined, 0, 16);
        Buffer.BlockCopy(table, 0, combined, 16, table.Length);
        var expected = SHA256.HashData(combined);

        CreateNamedBlobMethod(module, blobHolder, IntegritySeedBlobName, seed);
        CreateNamedBlobMethod(module, blobHolder, IntegrityExpectedBlobName, expected);

        var seedBlob = blobHolder.Methods.Single(m => m.Name == IntegritySeedBlobName);
        var expBlob  = blobHolder.Methods.Single(m => m.Name == IntegrityExpectedBlobName);

        var dispatchMd = EmitIntegrityChunkDispatchMethod(module, blobHolder, chunkGetters);
        EmitIntegrityModuleInitializer(module, blobHolder, verifyRef, seedBlob, expBlob, chunkGetters.Count, dispatchMd);
        return true;
    }

    private static MethodDefinition? FindBlobGetterForField(TypeDefinition holder, FieldDefinition field)
    {
        foreach (var md in holder.Methods.Where(m => m.HasBody))
        {
            foreach (var ins in md.Body.Instructions)
            {
                if (ins.OpCode != OpCodes.Ldtoken)
                    continue;
                if (ins.Operand is not FieldReference fr)
                    continue;
                if (!fr.Name.StartsWith("__data_", StringComparison.Ordinal))
                    continue;
                if (fr.Resolve() == field)
                    return md;
            }
        }

        return null;
    }

    private static MethodDefinition? EmitIntegrityChunkDispatchMethod(
        ModuleDefinition module,
        TypeDefinition holder,
        List<MethodDefinition> chunkGetters)
    {
        if (chunkGetters.Count == 0)
            return null;

        var retType = new ArrayType(module.TypeSystem.Byte);
        var md = new MethodDefinition(
            IntegrityChunkDispatchName,
            MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.HideBySig,
            retType);
        md.Parameters.Add(new ParameterDefinition("i", ParameterAttributes.None, module.TypeSystem.Int32));
        holder.Methods.Add(md);

        var body = new MethodBody(md);
        md.Body = body;
        var il = body.GetILProcessor();

        var n            = chunkGetters.Count;
        var switchTargets = new Instruction[n];
        for (var i = 0; i < n; i++)
            switchTargets[i] = Instruction.Create(OpCodes.Call, module.ImportReference(chunkGetters[i]));

        var ldarg0   = Instruction.Create(OpCodes.Ldarg_0);
        var sw       = Instruction.Create(OpCodes.Switch, switchTargets);
        var defNull  = Instruction.Create(OpCodes.Ldnull);
        var callFail = Instruction.Create(OpCodes.Call, ImportEnvironmentFailFastString(module));

        il.Append(ldarg0);
        il.Append(sw);
        il.Append(defNull);
        il.Append(callFail);

        for (var i = 0; i < n; i++)
        {
            il.Append(switchTargets[i]);
            il.Append(Instruction.Create(OpCodes.Ret));
        }

        RecomputeBody(md);
        return md;
    }

    private static void EmitIntegrityModuleInitializer(
        ModuleDefinition module,
        TypeDefinition holder,
        MethodReference verifyRef,
        MethodDefinition seedBlob,
        MethodDefinition expBlob,
        int chunkCount,
        MethodDefinition? dispatchMd)
    {
        var md = new MethodDefinition(
            IntegrityModuleInitName,
            MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.HideBySig,
            module.TypeSystem.Void);
        holder.Methods.Add(md);

        var body = new MethodBody(md);
        md.Body = body;
        var il = body.GetILProcessor();

        il.Emit(OpCodes.Call, module.ImportReference(seedBlob));
        il.Emit(OpCodes.Call, module.ImportReference(expBlob));
        EmitLdcI4(il, chunkCount);

        if (chunkCount is 0 || dispatchMd is null)
            il.Emit(OpCodes.Ldnull);
        else
        {
            il.Emit(OpCodes.Ldnull);
            il.Emit(OpCodes.Ldftn, module.ImportReference(dispatchMd));
            il.Emit(OpCodes.Newobj, ImportFuncInt32ByteArrayCtor(module));
        }

        il.Emit(OpCodes.Call, verifyRef);
        il.Emit(OpCodes.Ret);

        RecomputeBody(md);
        md.CustomAttributes.Add(new CustomAttribute(ImportModuleInitializerCtor(module)));
    }

    private static bool EmitNativeCoherencyModuleInitializer(
        ModuleDefinition module,
        TypeDefinition holder,
        MethodReference verifyRef,
        int byteCount)
    {
        const string nativeInitMethodName = "e79546fc324051a3";
        if (holder.Methods.Any(m => m.Name == nativeInitMethodName))
            return false;

        var md = new MethodDefinition(
            nativeInitMethodName,
            MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.HideBySig,
            module.TypeSystem.Void);
        holder.Methods.Add(md);

        var body = new MethodBody(md);
        md.Body = body;
        var il = body.GetILProcessor();
        EmitLdcI4(il, byteCount);
        il.Emit(OpCodes.Call, verifyRef);
        il.Emit(OpCodes.Ret);

        RecomputeBody(md);
        md.CustomAttributes.Add(new CustomAttribute(ImportModuleInitializerCtor(module)));
        return true;
    }

    /// <summary>
    /// Emits a module initializer that calls <c>AntiDebug.LikelyUnderDebugger()</c> at process startup.
    /// Thread.Sleep is intentionally NOT called here — module initializers run with CLR type-init
    /// locks held and a blocking sleep can deadlock the startup sequence. The timing-based check
    /// runs later via <c>CheckTimingOnce</c> which is called from the first instrumented method.
    /// </summary>
    private static bool EmitAntiDebugModuleInitializer(
        ModuleDefinition module, TypeDefinition holder,
        MethodReference likelyUnderDebugger, MethodReference environmentExit)
    {
        if (holder.Methods.Any(m => m.Name == AntiDebugModuleInitName))
            return false;

        var md = new MethodDefinition(
            AntiDebugModuleInitName,
            MethodAttributes.Static | MethodAttributes.Private | MethodAttributes.HideBySig,
            module.TypeSystem.Void);
        holder.Methods.Add(md);

        var body = new MethodBody(md);
        md.Body = body;
        var il = body.GetILProcessor();

        // if (LikelyUnderDebugger()) Environment.Exit(0);
        var retInstr = Instruction.Create(OpCodes.Ret);
        il.Emit(OpCodes.Call, likelyUnderDebugger);
        il.Emit(OpCodes.Brfalse, retInstr);
        il.Emit(OpCodes.Ldc_I4_0);
        il.Emit(OpCodes.Call, environmentExit);
        il.Append(retInstr);

        RecomputeBody(md);
        md.CustomAttributes.Add(new CustomAttribute(ImportModuleInitializerCtor(module)));
        return true;
    }

    private static int GetNativeCoherencyByteCount(ModuleDefinition module)
    {
        var attr = module.Assembly.CustomAttributes.FirstOrDefault(a => a.AttributeType.FullName == VerifyNativeCoherencyAttr);
        if (attr is null || attr.ConstructorArguments.Count < 1)
            return 512;

        var ca = attr.ConstructorArguments[0];
        if (ca.Type.MetadataType != MetadataType.Int32)
            return 512;

        var v = (int)ca.Value;
        return v > 0 && v <= 65536 ? v : 512;
    }
}
