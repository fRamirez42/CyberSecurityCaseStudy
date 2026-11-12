package cryptoguard.utils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Objects;

/** File creation and byte-level utilities for reproducible CryptoGuard experiments. */
public final class FileUtils {
    private static final SecureRandom RANDOM = new SecureRandom();

    private FileUtils() { }

    /** Generate a sample file containing exactly sizeBytes random bytes. */
    public static Path generateTestFile(Path destination, int sizeBytes) throws IOException {
        Objects.requireNonNull(destination, "destination");
        if (sizeBytes < 0) {
            throw new IllegalArgumentException("sizeBytes must be nonnegative");
        }
        byte[] data = new byte[sizeBytes];
        RANDOM.nextBytes(data);
        Path parent = destination.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        return Files.write(destination, data);
    }

    public static byte[] readFile(Path path) throws IOException {
        return Files.readAllBytes(Objects.requireNonNull(path, "path"));
    }

    public static Path writeFile(Path path, byte[] data) throws IOException {
        Objects.requireNonNull(path, "path");
        Objects.requireNonNull(data, "data");
        Path parent = path.toAbsolutePath().getParent();
        if (parent != null) Files.createDirectories(parent);
        return Files.write(path, data);
    }

    /** Copy a file and flip one bit in its first byte to simulate tampering. */
    public static Path createTamperedCopy(Path original, Path destination) throws IOException {
        byte[] data = readFile(original);
        if (data.length == 0) {
            throw new IllegalArgumentException("Cannot tamper with an empty file");
        }
        data[0] ^= 0x01;
        return writeFile(destination, data);
    }

    /** Generate the three file sizes specified in the research methodology. */
    public static void generateStandardTestFiles(Path directory) throws IOException {
        generateTestFile(directory.resolve("sample_1KB.bin"), 1024);
        generateTestFile(directory.resolve("sample_100KB.bin"), 100 * 1024);
        generateTestFile(directory.resolve("sample_1MB.bin"), 1024 * 1024);
    }
}
