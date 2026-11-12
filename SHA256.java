package cryptoguard.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;

/** SHA-256 file hashing and verification against a trusted reference digest. */
public final class SHA256 {
    private SHA256() { }

    public static byte[] computeHash(Path file) throws IOException {
        Objects.requireNonNull(file, "file");
        MessageDigest digest = newDigest();
        try (InputStream in = new DigestInputStream(Files.newInputStream(file), digest)) {
            byte[] buffer = new byte[8192];
            while (in.read(buffer) != -1) {
                // DigestInputStream updates the digest as bytes are read.
            }
        }
        return digest.digest();
    }

    public static String computeHashHex(Path file) throws IOException {
        return HexFormat.of().formatHex(computeHash(file));
    }

    /** expectedHash must come from a trusted source, not the potentially modified file. */
    public static boolean verifyHash(Path file, byte[] expectedHash) throws IOException {
        Objects.requireNonNull(expectedHash, "expectedHash");
        return MessageDigest.isEqual(computeHash(file), expectedHash);
    }

    public static boolean verifyHashHex(Path file, String expectedHex) throws IOException {
        Objects.requireNonNull(expectedHex, "expectedHex");
        return verifyHash(file, HexFormat.of().parseHex(expectedHex));
    }

    private static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available in this Java runtime", e);
        }
    }
}
