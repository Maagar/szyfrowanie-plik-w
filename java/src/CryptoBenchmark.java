import java.io.*;
import java.nio.file.*;
import java.time.Instant;
import java.util.Arrays;

public class CryptoBenchmark {

    private static final String RESULTS_FILE   = System.getenv().getOrDefault(
            "RESULTS_FILE",   "/results/benchmark_results.csv");
    private static final String TEST_FILES_DIR = System.getenv().getOrDefault(
            "TEST_FILES_DIR", "/test-files");

    private static final int[] FILE_SIZES_MB = {10, 100, 1000};
    private static final int   RUNS          = 15;

    public static void main(String[] args) throws Exception {
        // === WARMUP START ===
        System.out.println("Warming up JVM (10,000 iterations)...");
        byte[] dummy = new byte[1024]; // 1KB for speed
        CipherStrategy warmupGcm = new AesGcmCipher();
        CipherStrategy warmupChacha = new ChaCha20Cipher();
        CipherStrategy warmupTdes = new TripleDesCipher();
        
        for (int i = 0; i < 10000; i++) {
            byte[] encGcm = warmupGcm.encrypt(dummy);
            warmupGcm.decrypt(encGcm);
            
            byte[] encChacha = warmupChacha.encrypt(dummy);
            warmupChacha.decrypt(encChacha);
            
            byte[] encTdes = warmupTdes.encrypt(dummy);
            warmupTdes.decrypt(encTdes);
        }
        dummy = null;
        System.gc();
        System.out.println("Warmup complete. Starting benchmarks.");
        // === WARMUP END ===

        for (int sizeMb : FILE_SIZES_MB) {
            Path testFile = Paths.get(TEST_FILES_DIR, "test_" + sizeMb + "mb.bin");
            runBenchmark("AES-256-GCM",      new AesGcmCipher(),   testFile, sizeMb);
            runBenchmark("ChaCha20-Poly1305", new ChaCha20Cipher(), testFile, sizeMb);
            runBenchmark("TripleDES",        new TripleDesCipher(), testFile, sizeMb);
        }

        System.out.println(RESULTS_FILE);
    }

    private static void runBenchmark(String algorithm, CipherStrategy cipher,
                                     Path testFile, int sizeMb) throws Exception {
        System.out.printf("[Java] %s | %d MB%n", algorithm, sizeMb);

        byte[] original = Files.readAllBytes(testFile);

        long[] encMs = new long[RUNS];
        long[] decMs = new long[RUNS];
        long[] ramMb = new long[RUNS];
        boolean integrity = true;

        byte[] warmupData = Arrays.copyOf(original, Math.min(original.length, 1024 * 1024));
        for (int w = 0; w < 3; w++) {
            cipher.decrypt(cipher.encrypt(warmupData));
        }

        for (int i = 0; i < RUNS; i++) {
            Runtime rt = Runtime.getRuntime();
            rt.gc();
            long ramBefore = rt.totalMemory() - rt.freeMemory();

            long t0 = System.nanoTime();
            byte[] encrypted = cipher.encrypt(original);
            long t1 = System.nanoTime();

            long t2 = System.nanoTime();
            byte[] decrypted = cipher.decrypt(encrypted);
            long t3 = System.nanoTime();

            long ramAfter = rt.totalMemory() - rt.freeMemory();

            encMs[i] = (t1 - t0) / 1_000_000;
            decMs[i] = (t3 - t2) / 1_000_000;
            ramMb[i] = (ramAfter - ramBefore) / (1024 * 1024);

            if (!Arrays.equals(original, decrypted)) integrity = false;
        }

        appendCsvRow("Java-warmup", algorithm, sizeMb,
                median(encMs), median(decMs), median(ramMb), integrity);

        System.out.printf("  encrypt=%d ms  decrypt=%d ms  ram=%d MB  ok=%b%n",
                median(encMs), median(decMs), median(ramMb), integrity);
    }

    private static void appendCsvRow(String lang, String algo, int sizeMb,
                                     long encMs, long decMs, long ramMb,
                                     boolean integrity) throws IOException {
        try (PrintWriter pw = new PrintWriter(
                new FileWriter(Paths.get(RESULTS_FILE).toFile(), true))) {
            pw.printf("%s,%s,%d,%d,%d,%d,%b,%s%n",
                    lang, algo, sizeMb, encMs, decMs, ramMb,
                    integrity, Instant.now());
        }
    }

    private static long median(long[] arr) {
        long[] s = arr.clone();
        Arrays.sort(s);
        return s[s.length / 2];
    }
}