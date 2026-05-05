using Mono.Cecil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    private const string StringEncryptAttr     = "DotNetProtect.StringEncryptAttribute";
    private const string ControlFlowAttr       = "DotNetProtect.ObfuscateControlFlowAttribute";
    private const string PreserveAttr          = "DotNetProtect.PreserveAttribute";
    private const string ProtectMembersAttr    = "DotNetProtect.ProtectMembersAttribute";
    private const string InjectAntiDebugAttr   = "DotNetProtect.InjectAntiDebugAttribute";
    private const string AntiDebugAttr         = "DotNetProtect.AntiDebugAttribute";
    private const string VerifyIntegrityAttr   = "DotNetProtect.VerifyIntegrityAttribute";
    private const string FullProtectAttr       = "DotNetProtect.FullProtectAttribute";
    private const string ObfuscateNamesAttr    = "DotNetProtect.ObfuscateNamesAttribute";
    private const string PeProtectAttr         = "DotNetProtect.PeProtectAttribute";
    private const string VerifyNativeCoherencyAttr = "DotNetProtect.VerifyNativeExecutableCoherencyAttribute";

    /// <summary>Stable opaque names on the blob-holder type (must not change between weaves).</summary>
    private const string BlobHolderTypeName        = "a7f3c9e18d204b5a9c1e2f8d0b4a6c3e";
    private const string BlobHolderMasterKeyMethod = "b2c8e1f9d0a47356";
    private const string BlobHolderMkFragment0     = "c4d9a2e7f1038456";
    private const string BlobHolderMkFragment1     = "d5e0b3f8a2149567";
    private const string BlobHolderMkFragment2     = "e6f1c4a9b3250678";
    private const string BlobHolderMkFragment3     = "f8a2c5d8e3461023";
    private const string BlobHolderMkFragment4     = "a9b3d6e9f4572134";
    private const string BlobMethodNamePrefix      = "f7a28c91";

    private const string IntegritySeedBlobName      = "a39102c84ef756b8";
    private const string IntegrityExpectedBlobName  = "b48213d95f0867c9";
    private const string IntegrityModuleInitName    = "c59324ea613978da";
    private const string IntegrityChunkDispatchName = "d68435fb270948e2";
    private const string AntiDebugModuleInitName    = "e93b57f1a2084c6d";

    /// <summary>Resolved primitive literal decryptors (byte[] + XOR key → value).</summary>
    private readonly record struct ConstantDecrypters(
        MethodReference Int32,
        MethodReference Int64,
        MethodReference Single,
        MethodReference Double);

    /// <summary>Resolved <c>AntiDebug.LikelyUnderDebugger</c> + <c>Environment.Exit</c> for prologue injection.</summary>
    private readonly record struct AntiDebugInjector(
        MethodReference LikelyUnderDebugger,
        MethodReference EnvironmentExit);

    /// <summary>
    /// FieldRVA infrastructure cached once per weaver run (single-module CLI tool).
    /// Holds a reference to <c>RuntimeHelpers.InitializeArray</c> so blob methods use compact
    /// RVA data instead of element-by-element <c>stelem.i1</c> sequences —
    /// significantly smaller native AOT output.
    /// The <c>__StaticArrayInitTypeSize__N</c> nested structs live inside <c>blobHolder</c>
    /// (not in <c>&lt;PrivateImplementationDetails&gt;</c>) to avoid cross-type access violations.
    /// </summary>
    private readonly record struct RvaInfrastructure(MethodReference InitializeArray);

    public static int Main(string[] args)
    {
        if (args.Length is 0 || args[0] is "-h" or "--help")
        {
            Console.Error.WriteLine(
                "Usage: DotNetProtect.Weaver <assembly.dll> [options]\n" +
                "Options:\n" +
                "  --output <path>               Write protected assembly to <path> instead of overwriting input.\n" +
                "  -o <path>                     Alias for --output.\n" +
                "  --watermark <hex>             Embed a build fingerprint (hex bytes) as an obfuscated FieldRVA\n" +
                "                                  blob for leak tracing (e.g. --watermark DEADBEEF01020304).\n" +
                "  --lib <dir>                   Add assembly resolver search directory (repeatable).\n" +
                "  --strip-attributes            Remove DotNetProtect attributes from output.\n" +
                "  --no-strip-attributes         Keep DotNetProtect attributes in output (default).\n" +
                "  --rename-private-marked       Rename private members that carry protection attributes.\n" +
                "  --full-metadata               Rename all non-public types, methods, fields, and properties.\n" +
                "  --pe-protect                  Strip PE/ELF metadata (Rich header, debug directory, timestamps).\n" +
                "  --protect-binary-only <path>  Patch a native PE/ELF on disk without weaving IL.\n" +
                "  [assembly: DotNetProtect.VerifyIntegrity] embeds a build-time keyed SHA-256 over blob\n" +
                "    FieldRVA payloads and verifies them via a module initializer at startup.");
            return args.Length is 0 ? 1 : 0;
        }

        if (args.Length >= 2 && string.Equals(args[0], "--protect-binary-only", StringComparison.OrdinalIgnoreCase))
        {
            var binaryPath = Path.GetFullPath(args[1]);
            if (!File.Exists(binaryPath))
            {
                Console.Error.WriteLine($"Binary not found: {binaryPath}");
                return 2;
            }

            ApplyUnifiedBinaryProtection(binaryPath);
            return 0;
        }

        var path = Path.GetFullPath(args[0]);
        var extraLibDirs = new List<string>();
        var stripAttributes = false;
        var renamePrivateMarked = false;
        var fullMetadata = false;
        var peProtectFlag = false;
        string? outputOverride = null;
        byte[]? watermarkBytes = null;
        for (var i = 1; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--lib", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                extraLibDirs.Add(Path.GetFullPath(args[++i]));
            else if ((string.Equals(args[i], "--output", StringComparison.OrdinalIgnoreCase) ||
                      string.Equals(args[i], "-o", StringComparison.OrdinalIgnoreCase)) && i + 1 < args.Length)
                outputOverride = Path.GetFullPath(args[++i]);
            else if (string.Equals(args[i], "--watermark", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                var hex = args[++i].Replace("-", "", StringComparison.Ordinal)
                                   .Replace(" ", "", StringComparison.Ordinal);
                try { watermarkBytes = Convert.FromHexString(hex); }
                catch { Console.Error.WriteLine("--watermark: invalid hex string, ignoring."); }
            }
            else if (string.Equals(args[i], "--strip-attributes", StringComparison.OrdinalIgnoreCase))
                stripAttributes = true;
            else if (string.Equals(args[i], "--no-strip-attributes", StringComparison.OrdinalIgnoreCase))
                stripAttributes = false;
            else if (string.Equals(args[i], "--rename-private-marked", StringComparison.OrdinalIgnoreCase))
                renamePrivateMarked = true;
            else if (string.Equals(args[i], "--full-metadata", StringComparison.OrdinalIgnoreCase))
                fullMetadata = true;
            else if (string.Equals(args[i], "--pe-protect", StringComparison.OrdinalIgnoreCase))
                peProtectFlag = true;
        }

        var outputPath = outputOverride ?? path;

        if (!File.Exists(path))
        {
            Console.Error.WriteLine($"Assembly not found: {path}");
            return 2;
        }

        var resolver = new DefaultAssemblyResolver();
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir))
            resolver.AddSearchDirectory(dir);

        foreach (var lib in extraLibDirs)
        {
            if (Directory.Exists(lib))
                resolver.AddSearchDirectory(lib);
        }

        var envPaths = Environment.GetEnvironmentVariable("DOTNETPROTECT_ASSEMBLY_SEARCH_PATHS");
        if (!string.IsNullOrWhiteSpace(envPaths))
        {
            foreach (var p in envPaths.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (Directory.Exists(p))
                    resolver.AddSearchDirectory(p);
            }
        }

        // Rewritten IL invalidates sequence points; skip PDB to avoid Portable PDB reader crashes.
        var reader = new ReaderParameters
        {
            AssemblyResolver = resolver,
            ReadWrite = true,
            ReadSymbols = false,
        };

        using var module = ModuleDefinition.ReadModule(path, reader);

        // Reset per-module RVA cache (single-run tool, but be explicit).
        s_rvaCache = null;

        var needsStringDecrypt = ModuleUsesStringEncryption(module);
        MethodReference? stringDecrypt = null;
        if (needsStringDecrypt)
        {
            stringDecrypt = FindDecryptMethod(module);
            if (stringDecrypt is null)
            {
                Console.Error.WriteLine(
                    "Could not resolve DotNetProtect.Runtime.StringDecrypt.FromAes256CbcUtf8 — add a reference to the DotNetProtect assembly.");
                return 3;
            }
        }

        var needsControlFlow = ModuleUsesObfuscateControlFlow(module);
        ConstantDecrypters? constantDec = null;
        if (needsControlFlow)
        {
            constantDec = FindConstantDecrypters(module);
            if (constantDec is null)
            {
                Console.Error.WriteLine(
                    "Could not resolve DotNetProtect.Runtime.ConstantDecrypt (FromXorInt32/Int64/Single/Double) — add a reference to the DotNetProtect assembly.");
                return 3;
            }
        }

        var needsAntiDebug = ModuleUsesInjectAntiDebug(module);
        AntiDebugInjector? antiDebugInjector = null;
        if (needsAntiDebug)
        {
            antiDebugInjector = FindAntiDebugInjector(module);
            if (antiDebugInjector is null)
            {
                Console.Error.WriteLine(
                    "Could not resolve DotNetProtect.Runtime.AntiDebug.LikelyUnderDebugger — add a reference to the DotNetProtect assembly.");
                return 3;
            }
        }

        TypeDefinition? blobHolder = null;
        var blobIndex = 0;
        var changed = false;
        MethodDefinition? masterKeyMethod = null;
        byte[]? masterKeyBytes = null;

        var methodsToRename = new HashSet<MethodDefinition>();
        var fieldsToRename = new HashSet<FieldDefinition>();
        if (renamePrivateMarked && !fullMetadata)
            CollectRenameCandidates(module, methodsToRename, fieldsToRename);

        // [assembly: AntiDebug] applies to every eligible method in the assembly.
        var assemblyAntiDebug = HasAttribute(module.Assembly, AntiDebugAttr);

        foreach (var type in module.GetTypes())
        {
            // Class-level attribute propagation flags.
            var typePreserved      = HasAttribute(type, PreserveAttr);
            var hasFullProtect     = !typePreserved && HasAttribute(type, FullProtectAttr);
            var typeStringEncrypt  = !typePreserved && (HasAttribute(type, StringEncryptAttr) || HasAttribute(type, ProtectMembersAttr) || hasFullProtect);
            var typeCf             = !typePreserved && (HasAttribute(type, ProtectMembersAttr) || hasFullProtect);
            var typeInjectAd       = !typePreserved && (assemblyAntiDebug || HasAttribute(type, InjectAntiDebugAttr) || HasAttribute(type, AntiDebugAttr) || hasFullProtect);

            foreach (var method in type.Methods.Where(m => m.HasBody))
            {
                var memberPreserved   = typePreserved || HasAttribute(method, PreserveAttr);
                var hasStringEncrypt  = !memberPreserved && (HasAttribute(method, StringEncryptAttr) || typeStringEncrypt);
                var hasCf             = !memberPreserved && (HasAttribute(method, ControlFlowAttr) || typeCf);
                var hasAntiDebug      = !memberPreserved && (HasAttribute(method, InjectAntiDebugAttr) || HasAttribute(method, AntiDebugAttr) || typeInjectAd);

                if (!hasStringEncrypt && !hasCf && !hasAntiDebug)
                    continue;

                // Order matters: anti-debug first so its injected ldc.i4 also gets CF-obfuscated below.
                if (hasAntiDebug && antiDebugInjector is not null &&
                    InjectAntiDebugPrologue(method, antiDebugInjector.Value))
                    changed = true;

                if (hasStringEncrypt)
                {
                    blobHolder ??= EnsureBlobHolder(module);
                    if (masterKeyMethod is null)
                        masterKeyMethod = EnsureMasterKeyMethod(module, blobHolder, out masterKeyBytes);

                    if (EncryptStringsInMethod(module, method, blobHolder!, ref blobIndex, stringDecrypt!, masterKeyMethod, masterKeyBytes!))
                        changed = true;
                }

                if (hasCf)
                {
                    blobHolder ??= EnsureBlobHolder(module);
                    if (constantDec is not null)
                    {
                        // Opaque predicates run first so their ldc.i4 constants are encrypted by the literal pass below.
                        if (InjectOpaquePredicatesInMethod(module, method, blobHolder, ref blobIndex, constantDec.Value))
                            changed = true;
                        if (ObfuscatePrimitiveLiteralsInMethod(module, method, blobHolder, ref blobIndex, constantDec.Value))
                            changed = true;
                    }
                }

                if (hasFullProtect && !memberPreserved && IndirectifySomeCallsInMethod(module, method))
                    changed = true;
            }

            foreach (var field in type.Fields)
            {
                if (typePreserved || HasAttribute(field, PreserveAttr))
                    continue;

                if (!HasAttribute(field, StringEncryptAttr) && !typeStringEncrypt)
                    continue;

                blobHolder ??= EnsureBlobHolder(module);
                if (masterKeyMethod is null)
                    masterKeyMethod = EnsureMasterKeyMethod(module, blobHolder, out masterKeyBytes);

                if (EncryptStringFieldInitializers(module, field, blobHolder!, ref blobIndex, stringDecrypt!, masterKeyMethod, masterKeyBytes!))
                    changed = true;
            }
        }

        if (ModuleUsesVerifyIntegrity(module))
        {
            var integrityVerify = FindIntegrityVerifyMethod(module);
            if (integrityVerify is null)
            {
                Console.Error.WriteLine(
                    "Could not resolve DotNetProtect.Runtime.Integrity.VerifyTableOrFail — add a reference to the DotNetProtect assembly.");
                return 3;
            }

            blobHolder ??= EnsureBlobHolder(module);
            if (ApplyIntegrityManifest(module, blobHolder, integrityVerify))
                changed = true;
        }

        if (ModuleUsesVerifyNativeCoherency(module))
        {
            var nativeVerify = FindNativeTextIntegrityVerifyMethod(module);
            if (nativeVerify is null)
            {
                Console.Error.WriteLine(
                    "Could not resolve DotNetProtect.Runtime.NativeTextIntegrity.VerifyProcessImageMatchesOnDiskOrFail — add a reference to the DotNetProtect assembly.");
                return 3;
            }

            blobHolder ??= EnsureBlobHolder(module);
            if (EmitNativeCoherencyModuleInitializer(module, blobHolder, nativeVerify, GetNativeCoherencyByteCount(module)))
                changed = true;
        }

        if (needsAntiDebug && antiDebugInjector is not null)
        {
            blobHolder ??= EnsureBlobHolder(module);
            if (EmitAntiDebugModuleInitializer(module, blobHolder,
                    antiDebugInjector.Value.LikelyUnderDebugger,
                    antiDebugInjector.Value.EnvironmentExit))
                changed = true;
        }

        // Watermark: embed a build-specific fingerprint as an XOR-obfuscated FieldRVA blob.
        // The blob is unreferenced by any method — it blends with crypto blobs but can be
        // located by the build owner who knows the original bytes and the marker prefix.
        if (watermarkBytes is { Length: > 0 })
        {
            blobHolder ??= EnsureBlobHolder(module);
            EmbedWatermark(module, blobHolder, watermarkBytes);
            changed = true;
        }

        var metadataChanged = false;
        if (fullMetadata)
            metadataChanged = ApplyFullMetadataMangling(module);
        else if (renamePrivateMarked && (methodsToRename.Count > 0 || fieldsToRename.Count > 0))
            metadataChanged = ApplyPrivateMarkedRenames(module, methodsToRename, fieldsToRename);

        // Attribute-based name mangling ([ObfuscateNames]) — runs independently of CLI flags,
        // skipped when --full-metadata already renamed everything.
        if (!fullMetadata && ModuleUsesObfuscateNames(module))
        {
            var attrTypes   = new HashSet<TypeDefinition>();
            var attrMethods = new HashSet<MethodDefinition>();
            var attrFields  = new HashSet<FieldDefinition>();
            CollectAttributeNameCandidates(module, attrTypes, attrMethods, attrFields);
            if (ApplyAttributeNameRenames(module, attrTypes, attrMethods, attrFields))
                metadataChanged = true;
        }

        if ((changed || metadataChanged) && stripAttributes)
            StripProtectionAttributes(module);

        // PE protection: strip cosmetic assembly metadata attributes before writing.
        var peProtect = peProtectFlag || ModuleUsesPeProtect(module);
        if (peProtect)
        {
            if (StripAssemblyInfoAttributes(module))
                metadataChanged = true;
        }

        if (!changed && !metadataChanged)
        {
            Console.WriteLine("DotNetProtect.Weaver: no marked members, string fields, or metadata pass; assembly unchanged.");
            return 0;
        }

        var writer = new WriterParameters { WriteSymbols = false };
        var tempPath = outputPath + ".dotnetprotect.tmp";

        var outputDir = Path.GetDirectoryName(outputPath);
        if (!string.IsNullOrEmpty(outputDir) && !Directory.Exists(outputDir))
            Directory.CreateDirectory(outputDir);

        module.Write(tempPath, writer);
        try
        {
            File.Move(tempPath, outputPath, overwrite: true);
        }
        catch (IOException)
        {
            try { File.Delete(tempPath); } catch (IOException) { }
            throw;
        }

        // Remove stale PDB next to the output (not next to the input, which may differ).
        var pdbPath = Path.ChangeExtension(outputPath, "pdb");
        if (File.Exists(pdbPath))
        {
            try { File.Delete(pdbPath); }
            catch (IOException) { /* Leave stale PDB if locked; better than crashing the build. */ }
        }

        // PE binary patching runs after the file is in its final location.
        if (peProtect)
            ApplyPeBinaryProtection(outputPath);

        var summary = BuildProtectionSummary(needsStringDecrypt, needsControlFlow, needsAntiDebug, metadataChanged, watermarkBytes is { Length: > 0 });
        var destination = string.Equals(outputPath, path, StringComparison.Ordinal) ? outputPath : $"{outputPath} (from {path})";
        Console.WriteLine($"DotNetProtect.Weaver: wrote {destination} [{summary}]");
        return 0;
    }

    private static string BuildProtectionSummary(
        bool stringEncrypt, bool controlFlow, bool antiDebug, bool metadataChanged, bool watermark)
    {
        var parts = new List<string>(5);
        if (stringEncrypt)   parts.Add("string-encrypt");
        if (controlFlow)     parts.Add("cf-obfuscate");
        if (antiDebug)       parts.Add("anti-debug");
        if (metadataChanged) parts.Add("metadata-mangle");
        if (watermark)       parts.Add("watermark");
        return parts.Count > 0 ? string.Join(", ", parts) : "pe-protect";
    }
}
