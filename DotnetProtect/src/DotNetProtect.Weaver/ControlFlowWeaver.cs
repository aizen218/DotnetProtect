using System.Security.Cryptography;
using Mono.Cecil;
using Mono.Cecil.Cil;

namespace DotNetProtect.Weaver;

internal static partial class Program
{
    /// <summary>
    /// Replaces every <c>ldc.i4*</c> / <c>ldc.i8</c> in the method with blob + XOR decrypt (no float/double).
    /// </summary>
    private static bool ObfuscatePrimitiveLiteralsInMethod(
        ModuleDefinition module,
        MethodDefinition method,
        TypeDefinition blobHolder,
        ref int blobIndex,
        ConstantDecrypters dec)
    {
        if (!method.HasBody)
            return false;

        var body     = method.Body;
        var il       = body.GetILProcessor();
        var replaced = false;

        foreach (var ins in body.Instructions.ToArray())
        {
            if (TryGetLdcI4(ins, out var i4))
            {
                var key  = NextXorKey();
                var blob = XorCopy(BitConverter.GetBytes(i4), key);
                EmitPrimitiveLiteralReplacement(il, ins, module, blobHolder, ref blobIndex, blob, key, dec.Int32);
                replaced = true;
                continue;
            }

            if (ins.OpCode.Code == Code.Ldc_I8)
            {
                var i8   = (long)ins.Operand!;
                var key  = NextXorKey();
                var blob = XorCopy(BitConverter.GetBytes(i8), key);
                EmitPrimitiveLiteralReplacement(il, ins, module, blobHolder, ref blobIndex, blob, key, dec.Int64);
                replaced = true;
                continue;
            }

            if (ins.OpCode.Code == Code.Ldc_R4)
            {
                var f4   = (float)ins.Operand!;
                var key  = NextXorKey();
                var blob = XorCopy(BitConverter.GetBytes(f4), key);
                EmitPrimitiveLiteralReplacement(il, ins, module, blobHolder, ref blobIndex, blob, key, dec.Single);
                replaced = true;
                continue;
            }

            if (ins.OpCode.Code == Code.Ldc_R8)
            {
                var f8   = (double)ins.Operand!;
                var key  = NextXorKey();
                var blob = XorCopy(BitConverter.GetBytes(f8), key);
                EmitPrimitiveLiteralReplacement(il, ins, module, blobHolder, ref blobIndex, blob, key, dec.Double);
                replaced = true;
            }
        }

        if (replaced)
            RecomputeBody(method);

        return replaced;
    }

    /// <summary>
    /// Returns a cryptographically random non-zero 4-byte XOR key.
    /// 4-byte rolling key raises brute-force cost from 255 to 2^32 - 1 combinations.
    /// </summary>
    private static int NextXorKey()
    {
        Span<byte> buf = stackalloc byte[4];
        do { RandomNumberGenerator.Fill(buf); } while (buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0);
        return BitConverter.ToInt32(buf);
    }

    private static byte[] XorCopy(byte[] plain, int key)
    {
        Span<byte> keyBytes = stackalloc byte[4];
        BitConverter.TryWriteBytes(keyBytes, key);
        var r = new byte[plain.Length];
        for (var i = 0; i < plain.Length; i++)
            r[i] = (byte)(plain[i] ^ keyBytes[i % 4]);
        return r;
    }

    private static void EmitPrimitiveLiteralReplacement(
        ILProcessor il,
        Instruction ldcIns,
        ModuleDefinition module,
        TypeDefinition blobHolder,
        ref int blobIndex,
        byte[] blobBytes,
        int key,
        MethodReference decrypt)
    {
        var blobMethod  = CreateBlobMethod(module, blobHolder, blobIndex, blobBytes);
        blobIndex++;
        var callBlob    = Instruction.Create(OpCodes.Call, blobMethod);
        var loadKey     = Instruction.Create(OpCodes.Ldc_I4, key);
        var callDecrypt = Instruction.Create(OpCodes.Call, decrypt);
        ReplaceInstructions(il, ldcIns, [callBlob, loadKey, callDecrypt]);
    }

    // -------------------------------------------------------------------------
    // Opaque predicate injection
    //
    // For each method with CF enabled, before literal obfuscation runs, we locate
    // branch-target instructions (non-entry basic block leaders) and inject a
    // dead-branch block before each one:
    //
    //   call blobMethod      ← encrypted random constant C
    //   ldc.i4 xorKey        ← decryption key (will be encrypted by the literal pass)
    //   call FromXorInt32    ← always yields C
    //   ldc.i4 C             ← (will be encrypted by the literal pass)
    //   beq   skipDead       ← always taken (C == C) — decompiler sees a conditional branch
    //   ldnull               ← dead block
    //   throw                ← dead block
    //   nop                  ← skipDead anchor
    //   [original target instruction]
    //
    // The predicate constants (xorKey and C above) are plain ldc.i4 at injection time.
    // Because InjectOpaquePredicatesInMethod runs BEFORE ObfuscatePrimitiveLiteralsInMethod,
    // those ldc.i4 values are encrypted again by the literal pass, producing a double-layer:
    //   blob_key → decrypt → xorKey; blob_C → decrypt → C → compare.
    // This makes static analysis of each individual predicate significantly harder.
    //
    // Methods with exception handlers are skipped to avoid corrupting handler tables.
    // -------------------------------------------------------------------------

    private static bool InjectOpaquePredicatesInMethod(
        ModuleDefinition module,
        MethodDefinition method,
        TypeDefinition blobHolder,
        ref int blobIndex,
        ConstantDecrypters dec)
    {
        if (!method.HasBody || method.Body.HasExceptionHandlers) return false;

        var body = method.Body;
        var instructions = body.Instructions.ToArray();
        if (instructions.Length < 5) return false;

        // Collect branch targets — leaders of non-entry basic blocks.
        var branchTargets = new HashSet<Instruction>(ReferenceEqualityComparer.Instance);
        foreach (var ins in instructions)
        {
            if (ins.Operand is Instruction t)
                branchTargets.Add(t);
            else if (ins.Operand is Instruction[] targets)
                foreach (var bt in targets)
                    branchTargets.Add(bt);
        }

        // Skip method entry (index 0) — anti-debug prologue already sits there.
        branchTargets.Remove(instructions[0]);
        if (branchTargets.Count == 0) return false;

        var il  = body.GetILProcessor();
        var any = false;
        var count = 0;
        Span<byte> plainBytes = stackalloc byte[4];

        foreach (var target in branchTargets)
        {
            if (count >= 3) break; // limit per-method to avoid code bloat

            RandomNumberGenerator.Fill(plainBytes);
            var plainInt = BitConverter.ToInt32(plainBytes);
            var xorKey   = NextXorKey();
            var encBytes = XorCopy(plainBytes.ToArray(), xorKey);
            var blobMethod = CreateBlobMethod(module, blobHolder, blobIndex++, encBytes);

            var callBlob    = Instruction.Create(OpCodes.Call, blobMethod);
            var ldKey       = Instruction.Create(OpCodes.Ldc_I4, xorKey);
            var callDecrypt = Instruction.Create(OpCodes.Call, dec.Int32);
            var skipDead    = Instruction.Create(OpCodes.Nop);
            var ldNull      = Instruction.Create(OpCodes.Ldnull);
            var throwIns    = Instruction.Create(OpCodes.Throw);

            // 3 rotating patterns — each is an always-true predicate; the literal pass
            // encrypts the constant operands, producing a double-obfuscation layer.
            //   0: blob→C  ==  C            (compare decrypted value to itself)
            //   1: blob→x, x^x == 0         (any value XOR itself is zero)
            //   2: blob→x, x|~x == -1       (any value OR its complement is all-ones)
            var pattern = count % 3;
            Instruction branchOp;
            Instruction[] extraOps;

            switch (pattern)
            {
                case 1: // x ^ x == 0
                    extraOps = [Instruction.Create(OpCodes.Dup), Instruction.Create(OpCodes.Xor)];
                    branchOp = Instruction.Create(OpCodes.Beq, skipDead);
                    il.InsertBefore(target, callBlob);
                    il.InsertBefore(target, ldKey);
                    il.InsertBefore(target, callDecrypt);
                    foreach (var e in extraOps) il.InsertBefore(target, e);
                    il.InsertBefore(target, Instruction.Create(OpCodes.Ldc_I4_0));
                    il.InsertBefore(target, branchOp);
                    break;

                case 2: // x | ~x == -1
                    extraOps = [Instruction.Create(OpCodes.Dup), Instruction.Create(OpCodes.Not), Instruction.Create(OpCodes.Or)];
                    branchOp = Instruction.Create(OpCodes.Beq, skipDead);
                    il.InsertBefore(target, callBlob);
                    il.InsertBefore(target, ldKey);
                    il.InsertBefore(target, callDecrypt);
                    foreach (var e in extraOps) il.InsertBefore(target, e);
                    il.InsertBefore(target, Instruction.Create(OpCodes.Ldc_I4_M1));
                    il.InsertBefore(target, branchOp);
                    break;

                default: // C == C (original pattern)
                    branchOp = Instruction.Create(OpCodes.Beq, skipDead);
                    il.InsertBefore(target, callBlob);
                    il.InsertBefore(target, ldKey);
                    il.InsertBefore(target, callDecrypt);
                    il.InsertBefore(target, Instruction.Create(OpCodes.Ldc_I4, plainInt));
                    il.InsertBefore(target, branchOp);
                    break;
            }

            il.InsertBefore(target, ldNull);
            il.InsertBefore(target, throwIns);
            il.InsertBefore(target, skipDead);

            // Retarget ALL existing branches that point to `target` → enter via `callBlob`
            // so loop back-edges also traverse the predicate.
            foreach (var ins in instructions)
            {
                if (ins.Operand is Instruction op && op == target)
                    ins.Operand = callBlob;
                else if (ins.Operand is Instruction[] ops)
                    for (var i = 0; i < ops.Length; i++)
                        if (ops[i] == target) ops[i] = callBlob;
            }

            count++;
            any = true;
        }

        if (any) RecomputeBody(method);
        return any;
    }

    private static bool TryGetLdcI4(Instruction ins, out int value)
    {
        switch (ins.OpCode.Code)
        {
            case Code.Ldc_I4:    value = (int)ins.Operand!;    return true;
            case Code.Ldc_I4_S:  value = (sbyte)ins.Operand!;  return true;
            case Code.Ldc_I4_M1: value = -1; return true;
            case Code.Ldc_I4_0:  value =  0; return true;
            case Code.Ldc_I4_1:  value =  1; return true;
            case Code.Ldc_I4_2:  value =  2; return true;
            case Code.Ldc_I4_3:  value =  3; return true;
            case Code.Ldc_I4_4:  value =  4; return true;
            case Code.Ldc_I4_5:  value =  5; return true;
            case Code.Ldc_I4_6:  value =  6; return true;
            case Code.Ldc_I4_7:  value =  7; return true;
            case Code.Ldc_I4_8:  value =  8; return true;
            default:             value =  0; return false;
        }
    }
}
