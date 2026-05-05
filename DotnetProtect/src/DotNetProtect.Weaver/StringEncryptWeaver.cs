using System.Security.Cryptography;
using System.Text;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    private static bool EncryptStringsInMethod(
        ModuleDefinition module,
        MethodDefinition method,
        TypeDefinition blobHolder,
        ref int blobIndex,
        MethodReference decrypt,
        MethodDefinition masterKeyMethod,
        byte[] masterKeyBytes)
    {
        var body = method.Body;
        var il = body.GetILProcessor();
        var replaced = false;

        foreach (var ins in body.Instructions.ToArray())
        {
            if (ins.OpCode != OpCodes.Ldstr)
                continue;

            var plain = ins.Operand as string ?? string.Empty;
            var encrypted = EncryptUtf8Aes256Cbc(plain, masterKeyBytes);

            var blobMethod = CreateBlobMethod(module, blobHolder, blobIndex, encrypted);
            blobIndex++;

            var callBlob      = Instruction.Create(OpCodes.Call, blobMethod);
            var callMasterKey = Instruction.Create(OpCodes.Call, masterKeyMethod);
            var callDecrypt   = Instruction.Create(OpCodes.Call, decrypt);

            ReplaceInstructions(il, ins, [callBlob, callMasterKey, callDecrypt]);
            replaced = true;
        }

        if (replaced)
            RecomputeBody(method);

        return replaced;
    }

    private static bool EncryptStringFieldInitializers(
        ModuleDefinition module,
        FieldDefinition field,
        TypeDefinition blobHolder,
        ref int blobIndex,
        MethodReference decrypt,
        MethodDefinition masterKeyMethod,
        byte[] masterKeyBytes)
    {
        if (field.HasConstant)
        {
            Console.WriteLine(
                $"DotNetProtect: [StringEncrypt] on const field '{field.FullName}' is not supported (value is in the Constant metadata table). Use static readonly string instead.");
            return false;
        }

        if (field.FieldType.FullName != "System.String")
            return false;

        var declaring = field.DeclaringType;
        if (declaring is null)
            return false;

        var any = false;
        foreach (var ctorLike in declaring.Methods.Where(m => m.HasBody))
        {
            if (!EncryptLdstrBeforeFieldStores(ctorLike, field, module, blobHolder, ref blobIndex, decrypt, masterKeyMethod, masterKeyBytes))
                continue;

            any = true;
        }

        return any;
    }

    /// <summary>
    /// Replaces every <c>ldstr</c> that is immediately followed (in IL order) by a store to <paramref name="field"/>.
    /// </summary>
    private static bool EncryptLdstrBeforeFieldStores(
        MethodDefinition method,
        FieldDefinition field,
        ModuleDefinition module,
        TypeDefinition blobHolder,
        ref int blobIndex,
        MethodReference decrypt,
        MethodDefinition masterKeyMethod,
        byte[] masterKeyBytes)
    {
        var body = method.Body;
        var il = body.GetILProcessor();
        var replaced = false;

        while (true)
        {
            var storeIndex = FindSequentialLdstrStoreToField(body, field);
            if (storeIndex < 0)
                break;

            var ldstr   = body.Instructions[storeIndex - 1];
            var plain   = ldstr.Operand as string ?? string.Empty;
            var encrypted = EncryptUtf8Aes256Cbc(plain, masterKeyBytes);
            var blobMethod = CreateBlobMethod(module, blobHolder, blobIndex, encrypted);
            blobIndex++;

            var callBlob      = Instruction.Create(OpCodes.Call, blobMethod);
            var callMasterKey = Instruction.Create(OpCodes.Call, masterKeyMethod);
            var callDecrypt   = Instruction.Create(OpCodes.Call, decrypt);
            ReplaceInstructions(il, ldstr, [callBlob, callMasterKey, callDecrypt]);
            replaced = true;
        }

        if (replaced)
            RecomputeBody(method);

        return replaced;
    }

    private static int FindSequentialLdstrStoreToField(MethodBody body, FieldDefinition field)
    {
        for (var i = 1; i < body.Instructions.Count; i++)
        {
            var ins = body.Instructions[i];
            if (ins.OpCode != OpCodes.Stsfld && ins.OpCode != OpCodes.Stfld)
                continue;
            if (ins.Operand is not FieldReference fr || fr.Resolve() != field)
                continue;
            if (body.Instructions[i - 1].OpCode != OpCodes.Ldstr)
                continue;
            return i;
        }

        return -1;
    }

    private static byte[] EncryptUtf8Aes256Cbc(string plain, byte[] masterKey256)
    {
        var utf8 = Encoding.UTF8.GetBytes(plain);
        using var aes = Aes.Create();
        aes.KeySize  = 256;
        aes.Mode     = CipherMode.CBC;
        aes.Padding  = PaddingMode.PKCS7;
        aes.Key      = masterKey256;
        aes.GenerateIV();
        var iv = aes.IV;
        using var enc   = aes.CreateEncryptor();
        var cipher      = enc.TransformFinalBlock(utf8, 0, utf8.Length);
        var result      = new byte[iv.Length + cipher.Length];
        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
        Buffer.BlockCopy(cipher, 0, result, iv.Length, cipher.Length);
        return result;
    }
}
