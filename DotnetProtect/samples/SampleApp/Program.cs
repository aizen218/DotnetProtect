using DotNetProtect;
using DotNetProtect.Runtime;

[assembly: VerifyIntegrity]
[assembly: PeProtect]
// [assembly: VerifyNativeExecutableCoherency(512)]  -- AOT-only, skip for IL build

namespace SampleApp;

[FullProtect]
internal static class Program
{
    [StringEncrypt]
    internal static readonly string GlobalField = "global-field-secret";

    [STAThread]
    [Preserve]
    private static void Main()
    {
        ShowSecrets();
        Console.WriteLine(GlobalField);
        ConfusingEntry();
        FloatingPoint();
        DemoPreserve();
        DemoProperty();
        DemoFullProtect();
    }

    // Hưởng [FullProtect]: string encrypt + constant obfuscation + anti-debug.
    private static void ShowSecrets()
    {
        var a   = "123";
        var msg = "Xin chào — chuỗi này được mã hóa AES-256-CBC lúc build.";
        Console.WriteLine(a);
        Console.WriteLine(msg);
    }

    // Integer constants → blob + XOR.
    private static void ConfusingEntry()
    {
        const int expected = 42;
        long hi = 40L;
        int  lo = 2;
        Console.WriteLine((int)hi + lo);
        if ((int)hi + lo != expected)
            throw new InvalidOperationException("Literal obfuscation regression.");
    }

    // Float / double constants → blob + XOR.
    private static void FloatingPoint()
    {
        const float  pi32 = 3.14159f;
        const double e64  = 2.718281828;
        var area = pi32 * 2f * 2f;
        Console.WriteLine($"area={area:0.000} e={e64:0.000}");
    }

    // [Preserve] override class-level [FullProtect] → method này giữ nguyên.
    [Preserve]
    private static void DemoPreserve()
    {
        const string tag = "NOT_ENCRYPTED";
        Console.WriteLine(tag);
    }

    private static void DemoProperty()
    {
        var box = new SecretBox { Token = "live-token-XYZ" };
        Console.WriteLine($"token-len={box.Token.Length}");
    }

    private static void DemoFullProtect()
    {
        // method này được bảo vệ bởi [FullProtect] trên class:
        // string → AES-256, constants → XOR blob, debugger check ở đầu method.
        var secret = "demo-[FullProtect]-string";
        var magic  = 0xDEAD_BEEF;
        Console.WriteLine($"{secret} / 0x{magic:X}");
    }
}

// [ObfuscateNames] trên type → rename type + toàn bộ non-public methods/fields/properties.
// Không cần CLI flag --rename-private-marked hay --full-metadata.
[ObfuscateNames]
internal sealed class SecretBox
{
    internal string Token { get; set; } = string.Empty;

    // [Preserve] trên property → giữ nguyên tên dù type có [ObfuscateNames].
    [Preserve]
    internal string PublicId { get; set; } = "kept-name";
}

// Class-level [StringEncrypt] không kéo theo CF/AntiDebug — chỉ string protection.
[StringEncrypt]
internal static class ConfigHelper
{
    internal static string GetConnectionString() =>
        "Server=localhost;Database=app;User Id=admin;Password=s3cr3t;";

    internal static string GetApiKey() =>
        "sk-prod-XXXXXXXXXXXXXXXXXXXX";

    [Preserve]
    internal static string GetPublicEndpoint() =>
        "https://api.example.com/v1";
}

// Demo [ObfuscateNames] trên từng member riêng lẻ (không cần đặt trên cả type).
internal static class PartialObfHelper
{
    // Method này sẽ được rename.
    [ObfuscateNames]
    internal static string GetInternalToken() => "internal-token-abc";

    // Method này giữ nguyên tên (không có [ObfuscateNames]).
    internal static string GetPublicVersion() => "1.0.0";
}
