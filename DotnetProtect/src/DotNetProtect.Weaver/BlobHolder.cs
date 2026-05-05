using System.Security.Cryptography;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    /// <summary>
    /// FieldRVA infrastructure cached once per weaver run (single-module CLI tool).
    /// Reset to null at the start of each <see cref="Main"/> invocation.
    /// </summary>
    private static RvaInfrastructure? s_rvaCache;

    private static TypeDefinition EnsureBlobHolder(ModuleDefinition module)
    {
        // Stable opaque identifiers only: randomizing per run would break idempotency (duplicate holders).
        const string ns = "";
        var existing = module.GetTypes().FirstOrDefault(t => t.Namespace == ns && t.Name == BlobHolderTypeName);
        if (existing is not null)
            return existing;

        var td = new TypeDefinition(
            ns,
            BlobHolderTypeName,
            TypeAttributes.NotPublic | TypeAttributes.AutoClass | TypeAttributes.Abstract | TypeAttributes.Sealed,
            module.TypeSystem.Object);

        module.Types.Add(td);
        return td;
    }

    /// <summary>
    /// Generates the 32-byte AES master key and stores it as three independent FieldRVA fragments
    /// XOR-combined to the real key; an internal aggregator forwards them to
    /// <c>StringDecrypt.CombineKey</c>. A casual <c>strings</c> / hex scan over the AOT binary
    /// will not reveal the key — all three random-looking 32-byte fragments must be located,
    /// identified, and XOR-combined.
    /// </summary>
    private static MethodDefinition EnsureMasterKeyMethod(ModuleDefinition module, TypeDefinition blobHolder, out byte[] key32)
    {
        if (blobHolder.Methods.Any(m => m.Name == BlobHolderMasterKeyMethod))
        {
            throw new InvalidOperationException(
                "DotNetProtect: assembly already contains generated key aggregator on the blob holder. Rebuild from a clean output to re-weave.");
        }

        var combineKey5 = FindCombineKey5Method(module)
            ?? throw new InvalidOperationException(
                "DotNetProtect: could not resolve DotNetProtect.Runtime.StringDecrypt.CombineKey5.");

        key32 = new byte[32];
        RandomNumberGenerator.Fill(key32);

        // pad1..pad4: random pads; part0 = key ^ pad1 ^ pad2 ^ pad3 ^ pad4.
        // All five blobs must be located and XOR-combined to recover the key.
        var pad1  = new byte[32]; RandomNumberGenerator.Fill(pad1);
        var pad2  = new byte[32]; RandomNumberGenerator.Fill(pad2);
        var pad3  = new byte[32]; RandomNumberGenerator.Fill(pad3);
        var pad4  = new byte[32]; RandomNumberGenerator.Fill(pad4);
        var part0 = new byte[32];
        for (var i = 0; i < 32; i++)
            part0[i] = (byte)(key32[i] ^ pad1[i] ^ pad2[i] ^ pad3[i] ^ pad4[i]);

        var mk0 = CreateNamedBlobMethod(module, blobHolder, BlobHolderMkFragment0, part0);
        var mk1 = CreateNamedBlobMethod(module, blobHolder, BlobHolderMkFragment1, pad1);
        var mk2 = CreateNamedBlobMethod(module, blobHolder, BlobHolderMkFragment2, pad2);
        var mk3 = CreateNamedBlobMethod(module, blobHolder, BlobHolderMkFragment3, pad3);
        var mk4 = CreateNamedBlobMethod(module, blobHolder, BlobHolderMkFragment4, pad4);

        var arrType = new ArrayType(module.TypeSystem.Byte);
        var aggregator = new MethodDefinition(
            BlobHolderMasterKeyMethod,
            MethodAttributes.Assembly | MethodAttributes.HideBySig | MethodAttributes.Static,
            arrType);
        blobHolder.Methods.Add(aggregator);

        var il = aggregator.Body.GetILProcessor();
        il.Emit(OpCodes.Call, mk0);
        il.Emit(OpCodes.Call, mk1);
        il.Emit(OpCodes.Call, mk2);
        il.Emit(OpCodes.Call, mk3);
        il.Emit(OpCodes.Call, mk4);
        il.Emit(OpCodes.Call, combineKey5);
        il.Emit(OpCodes.Ret);
        RecomputeBody(aggregator);

        return aggregator;
    }

    // -------------------------------------------------------------------------
    // Blob methods (FieldRVA + RuntimeHelpers.InitializeArray)
    //
    // Instead of emitting one stelem.i1 per byte (O(N) IL instructions that AOT
    // compiles to O(N) mov+store native instructions), we use the same pattern the
    // C# compiler generates for `new byte[] { … }`:
    //
    //   newarr byte
    //   dup
    //   ldtoken __data_XXXX   (FieldRVA field whose InitialValue = raw bytes)
    //   call RuntimeHelpers.InitializeArray
    //   ret
    //
    // In AOT this becomes a single memcpy from RVA data — much smaller and much
    // harder to distinguish from normal compiler-generated array initialization.
    // -------------------------------------------------------------------------

    private static MethodDefinition CreateBlobMethod(ModuleDefinition module, TypeDefinition holder, int index, byte[] bytes) =>
        CreateNamedBlobMethod(module, holder, BlobMethodNamePrefix + index.ToString("x8"), bytes);

    private static MethodDefinition CreateNamedBlobMethod(ModuleDefinition module, TypeDefinition holder, string name, byte[] bytes)
    {
        s_rvaCache ??= BuildRvaInfrastructure(module);
        var initArrayRef = s_rvaCache.Value.InitializeArray;

        // FieldRVA static field carrying the raw bytes.
        // Nested type lives in `holder` (same type as the field and methods) — no cross-type access issue.
        var arrayInitType = EnsureStaticArrayInitType(module, holder, bytes.Length);
        var dataField = new FieldDefinition(
            $"__data_{Convert.ToHexString(RandomNumberGenerator.GetBytes(6))}",
            FieldAttributes.Assembly | FieldAttributes.Static | FieldAttributes.InitOnly,
            arrayInitType);
        dataField.InitialValue = bytes; // Cecil sets HasFieldRVA automatically.
        holder.Fields.Add(dataField);

        // Small blob method: 6 IL instructions, independent of blob size.
        var arrType = new ArrayType(module.TypeSystem.Byte);
        var method = new MethodDefinition(
            name,
            MethodAttributes.Assembly | MethodAttributes.HideBySig | MethodAttributes.Static,
            arrType);
        holder.Methods.Add(method);

        var il = method.Body.GetILProcessor();
        il.Emit(OpCodes.Ldc_I4, bytes.Length);
        il.Emit(OpCodes.Newarr, module.TypeSystem.Byte);
        il.Emit(OpCodes.Dup);
        il.Emit(OpCodes.Ldtoken, dataField);
        il.Emit(OpCodes.Call, initArrayRef);
        il.Emit(OpCodes.Ret);

        RecomputeBody(method);
        return method;
    }

    private static RvaInfrastructure BuildRvaInfrastructure(ModuleDefinition module) =>
        new RvaInfrastructure(BuildInitializeArrayRef(module));

    /// <summary>
    /// Finds or creates a <c>__StaticArrayInitTypeSize__N</c> explicit-layout value type nested
    /// inside <paramref name="container"/> (the blob-holder type).
    /// Nesting inside the same type that holds the FieldRVA fields avoids cross-type
    /// accessibility violations when <c>ldtoken</c> is emitted.
    /// </summary>
    private static TypeReference EnsureStaticArrayInitType(ModuleDefinition module, TypeDefinition container, int size)
    {
        var name     = $"__StaticArrayInitTypeSize__{size}";
        var existing = container.NestedTypes.FirstOrDefault(t => t.Name == name);
        if (existing is not null)
            return existing;

        var valueTypeRef = new TypeReference("System", "ValueType", module, module.TypeSystem.CoreLibrary);
        var td = new TypeDefinition(
            "",
            name,
            TypeAttributes.NestedPrivate | TypeAttributes.ExplicitLayout | TypeAttributes.AnsiClass | TypeAttributes.Sealed,
            valueTypeRef);
        td.PackingSize = 1;
        td.ClassSize   = size;
        container.NestedTypes.Add(td);
        return td;
    }

    /// <summary>
    /// Builds an importable reference to
    /// <c>System.Runtime.CompilerServices.RuntimeHelpers.InitializeArray(Array, RuntimeFieldHandle)</c>.
    /// </summary>
    private static MethodReference BuildInitializeArrayRef(ModuleDefinition module)
    {
        var coreLib = module.TypeSystem.CoreLibrary;

        var runtimeHelpersRef = new TypeReference(
            "System.Runtime.CompilerServices", "RuntimeHelpers", module, coreLib);

        var arrayRef = new TypeReference("System", "Array", module, coreLib);

        var fieldHandleRef = new TypeReference("System", "RuntimeFieldHandle", module, coreLib)
        {
            IsValueType = true,
        };

        var methodRef = new MethodReference("InitializeArray", module.TypeSystem.Void, runtimeHelpersRef);
        methodRef.Parameters.Add(new ParameterDefinition(arrayRef));
        methodRef.Parameters.Add(new ParameterDefinition(fieldHandleRef));
        return module.ImportReference(methodRef);
    }
}
