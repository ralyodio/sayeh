package ir.sayeh.stego;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** PBKDF2-HMAC-SHA256 and AES-256-GCM. Mirrors crypto.go. */
public final class Crypto {

    public static final int KEY_LEN = 32;   // AES-256
    public static final int SALT_LEN = 16;
    public static final int NONCE_LEN = 12;
    public static final int TAG_BITS = 128;
    public static final int GCM_OVERHEAD = TAG_BITS / 8;

    public static final int DEFAULT_ITERATIONS = 600_000;
    public static final int MIN_ITERATIONS = 50_000;

    private static final SecureRandom RANDOM = new SecureRandom();

    private Crypto() {
    }

    public static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    /**
     * PBKDF2-HMAC-SHA256, implemented directly on top of Mac rather than
     * SecretKeyFactory.
     *
     * <p>This is deliberate. {@code PBEKeySpec} takes a {@code char[]}, and
     * different providers disagree on how to turn those characters into bytes
     * for non-ASCII input. Hashing the UTF-8 bytes ourselves makes a Persian
     * password derive the same key here as it does in the Go implementation,
     * on every device and every JVM.
     */
    public static byte[] pbkdf2(String password, byte[] salt, int iterations, int length)
            throws GeneralSecurityException {

        if (iterations < 1) {
            throw new GeneralSecurityException("iteration count must be positive");
        }

        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(passwordBytes, "HmacSHA256"));
        Arrays.fill(passwordBytes, (byte) 0);

        int hLen = mac.getMacLength();
        int blocks = (length + hLen - 1) / hLen;
        byte[] out = new byte[blocks * hLen];
        byte[] block = new byte[4];

        for (int i = 1; i <= blocks; i++) {
            block[0] = (byte) (i >>> 24);
            block[1] = (byte) (i >>> 16);
            block[2] = (byte) (i >>> 8);
            block[3] = (byte) i;

            mac.update(salt);
            mac.update(block);
            byte[] u = mac.doFinal();
            byte[] acc = u.clone();

            for (int c = 1; c < iterations; c++) {
                u = mac.doFinal(u);
                for (int k = 0; k < hLen; k++) {
                    acc[k] ^= u[k];
                }
            }
            System.arraycopy(acc, 0, out, (i - 1) * hLen, hLen);
        }

        byte[] key = Arrays.copyOf(out, length);
        Arrays.fill(out, (byte) 0);
        return key;
    }

    public static byte[] deriveKey(String password, byte[] salt, int iterations)
            throws GeneralSecurityException {
        if (password == null || password.isEmpty()) {
            throw new GeneralSecurityException("the password cannot be empty");
        }
        if (iterations < MIN_ITERATIONS) {
            throw new GeneralSecurityException("iteration count is below the safe minimum");
        }
        return pbkdf2(password, salt, iterations, KEY_LEN);
    }

    /** Overwrites key material. */
    public static void wipe(byte[] b) {
        if (b != null) {
            Arrays.fill(b, (byte) 0);
        }
    }

    public static byte[] seal(byte[] key, byte[] nonce, byte[] plaintext, byte[] aad)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext);
    }

    public static byte[] open(byte[] key, byte[] nonce, byte[] ciphertext, byte[] aad)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext);
    }
}
