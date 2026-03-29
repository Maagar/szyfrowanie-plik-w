using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

string resultsFile  = Environment.GetEnvironmentVariable("RESULTS_FILE")  ?? "/results/benchmark_results.csv";
string testFilesDir = Environment.GetEnvironmentVariable("TEST_FILES_DIR") ?? "/test-files";

int[] sizes = { 10, 100, 1000 };
const int Runs = 3;

foreach (int sizeMb in sizes)
{
    string path = Path.Combine(testFilesDir, $"test_{sizeMb}mb.bin");
    RunBenchmark("AES-256-GCM",      sizeMb, path, new AesBenchmark());
    RunBenchmark("ChaCha20-Poly1305", sizeMb, path, new ChaChaBenchmark());
}

Console.WriteLine($"{resultsFile}");

// -------------------------------------------------------------------------

void RunBenchmark(string algorithm, int sizeMb, string filePath, ICipher cipher)
{
    Console.WriteLine($"[C#] {algorithm} | {sizeMb} MB");

    byte[] original = File.ReadAllBytes(filePath);

    long[] encMs = new long[Runs];
    long[] decMs = new long[Runs];
    long[] ramMb = new long[Runs];
    bool integrity = true;

    for (int i = 0; i < Runs; i++)
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        long ramBefore = GC.GetTotalMemory(true);

        var sw = Stopwatch.StartNew();
        byte[] encrypted = cipher.Encrypt(original);
        sw.Stop();
        encMs[i] = sw.ElapsedMilliseconds;

        sw.Restart();
        byte[] decrypted = cipher.Decrypt(encrypted);
        sw.Stop();
        decMs[i] = sw.ElapsedMilliseconds;

        long ramAfter = GC.GetTotalMemory(false);
        ramMb[i] = (ramAfter - ramBefore) / (1024 * 1024);

        if (!original.AsSpan().SequenceEqual(decrypted))
            integrity = false;
    }

    long encMed = Median(encMs);
    long decMed = Median(decMs);
    long ramMed = Median(ramMb);

    AppendCsv("CSharp", algorithm, sizeMb, encMed, decMed, ramMed, integrity);
    Console.WriteLine($"  encrypt={encMed} ms  decrypt={decMed} ms  ram={ramMed} MB  ok={integrity}");
}

void AppendCsv(string lang, string algo, int sizeMb,
               long encMs, long decMs, long ramMb, bool integrity)
{
    string line = $"{lang},{algo},{sizeMb},{encMs},{decMs},{ramMb},{integrity.ToString().ToLower()},{DateTime.UtcNow:o}";
    File.AppendAllText(resultsFile, line + Environment.NewLine);
}

long Median(long[] arr)
{
    long[] s = (long[])arr.Clone();
    Array.Sort(s);
    return s[s.Length / 2];
}

// -------------------------------------------------------------------------

interface ICipher
{
    byte[] Encrypt(byte[] plaintext);
    byte[] Decrypt(byte[] ciphertext);
}

// AES-256-GCM
// Format: [ nonce (12 B) | tag (16 B) | ciphertext ]
class AesBenchmark : ICipher
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);

    public byte[] Encrypt(byte[] plaintext)
    {
        byte[] nonce      = RandomNumberGenerator.GetBytes(12);
        byte[] tag        = new byte[16];
        byte[] ciphertext = new byte[plaintext.Length];

        using var aes = new AesGcm(_key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        byte[] result = new byte[12 + 16 + ciphertext.Length];
        nonce.CopyTo(result, 0);
        tag.CopyTo(result, 12);
        ciphertext.CopyTo(result, 28);
        return result;
    }

    public byte[] Decrypt(byte[] blob)
    {
        byte[] nonce      = blob[0..12];
        byte[] tag        = blob[12..28];
        byte[] ciphertext = blob[28..];
        byte[] plaintext  = new byte[ciphertext.Length];

        using var aes = new AesGcm(_key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}

// ChaCha20-Poly1305
// Format: [ nonce (12 B) | tag (16 B) | ciphertext ]
class ChaChaBenchmark : ICipher
{
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);

    public byte[] Encrypt(byte[] plaintext)
    {
        byte[] nonce      = RandomNumberGenerator.GetBytes(12);
        byte[] tag        = new byte[16];
        byte[] ciphertext = new byte[plaintext.Length];

        using var chacha = new ChaCha20Poly1305(_key);
        chacha.Encrypt(nonce, plaintext, ciphertext, tag);

        byte[] result = new byte[12 + 16 + ciphertext.Length];
        nonce.CopyTo(result, 0);
        tag.CopyTo(result, 12);
        ciphertext.CopyTo(result, 28);
        return result;
    }

    public byte[] Decrypt(byte[] blob)
    {
        byte[] nonce      = blob[0..12];
        byte[] tag        = blob[12..28];
        byte[] ciphertext = blob[28..];
        byte[] plaintext  = new byte[ciphertext.Length];

        using var chacha = new ChaCha20Poly1305(_key);
        chacha.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}