package ir.sayeh.stego;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Desktop-runnable verification of the shared core.
 *
 * <p>Everything under test lives in classes that touch only the java and
 * javax namespaces, so the exact bytes that ship inside the APK can be checked
 * here against the Go implementation before ever reaching a phone.
 *
 * <pre>
 *   java ir.sayeh.stego.SelfTest                       run the checks
 *   java ir.sayeh.stego.SelfTest hide   IN OUT PASS    hide a secret (PASS may be "")
 *   java ir.sayeh.stego.SelfTest reveal IN PASS        extract a secret
 * </pre>
 */
public final class SelfTest {

    private static int failures = 0;

    public static void main(String[] args) throws Exception {
        if (args.length > 0) {
            cli(args);
            return;
        }

        check("PBKDF2-HMAC-SHA256 known-answer (RFC 7914 §11)", SelfTest::kdfVectors);
        check("zero-width codec round-trip, all byte values", SelfTest::codecRoundTrip);
        check("codec alphabets exclude U+200C (Persian ZWNJ)", SelfTest::noZwnj);
        check("hide/reveal round-trip without a password", () -> roundTrip("plain text", ""));
        check("hide/reveal round-trip with a password", () -> roundTrip("attack at dawn", "correct horse"));
        check("unicode payload survives (Persian + emoji)",
                () -> roundTrip("پیام محرمانه ۱۲۳ — mixed 🔐🕵️", "رمز عبور فارسی"));
        check("wrong password is rejected", SelfTest::wrongPassword);
        check("flipped ciphertext bit is rejected", SelfTest::tamper);
        check("padding hides the exact message length", SelfTest::padding);
        check("cover text is preserved verbatim", SelfTest::coverPreserved);
        check("legacy v1/v2 plain payloads still decode", SelfTest::legacy);
        check("cross-implementation vector matches Go", SelfTest::crossVector);

        if (failures > 0) {
            System.out.println("\n[!] SELF-TEST FAILED: " + failures + " check(s) failed.");
            System.exit(1);
        }
        System.out.println("\n[OK] All self-tests passed.");
    }

    // -----------------------------------------------------------------------

    private interface Check {
        void run() throws Exception;
    }

    private static void check(String name, Check c) {
        try {
            c.run();
            System.out.println("  ok    " + name);
        } catch (Throwable t) {
            System.out.println("  FAIL  " + name);
            System.out.println("          " + t);
            failures++;
        }
    }

    private static void expect(boolean cond, String message) {
        if (!cond) {
            throw new AssertionError(message);
        }
    }

    // -----------------------------------------------------------------------

    private static void kdfVectors() throws Exception {
        String[][] vectors = {
                {"passwd", "salt", "1", "64",
                        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
                                + "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"},
                {"Password", "NaCl", "80000", "64",
                        "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56"
                                + "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"},
                {"password", "salt", "4096", "32",
                        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
        };

        for (String[] v : vectors) {
            byte[] got = Crypto.pbkdf2(v[0], v[1].getBytes(StandardCharsets.UTF_8),
                    Integer.parseInt(v[2]), Integer.parseInt(v[3]));
            expect(hex(got).equals(v[4]),
                    "vector " + v[0] + "/" + v[1] + ": got " + hex(got));
        }
    }

    private static void codecRoundTrip() {
        byte[] data = new byte[256];
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) i;
        }
        for (int codec : new int[]{ZwCodec.B4, ZwCodec.B2}) {
            String encoded = ZwCodec.encode(data, codec);
            int half = encoded.length() / 2;
            String noisy = "سلام" + encoded.substring(0, half)
                    + " hello world " + encoded.substring(half) + "!";
            expect(Arrays.equals(ZwCodec.decode(noisy, codec), data),
                    ZwCodec.name(codec) + ": round-trip mismatch");
        }
    }

    private static void noZwnj() {
        expect(!ZwCodec.isCarrier('‌'), "U+200C is treated as a carrier");
        String persian = "نیم‌فاصله";
        expect(ZwCodec.strip(persian).equals(persian), "strip() mangled a Persian half-space");
    }

    private static void roundTrip(String secret, String password) throws Exception {
        String cover = "This is an ordinary looking sentence.";

        Stego.Options opts = new Stego.Options();
        opts.password = password;
        opts.iterations = Crypto.MIN_ITERATIONS; // keep the self-test fast

        String stego = Stego.hide(cover, secret, opts).text;
        String got = Stego.reveal(stego, password);
        expect(got.equals(secret), "recovered \"" + got + "\", want \"" + secret + "\"");
    }

    private static void wrongPassword() throws Exception {
        Stego.Options opts = new Stego.Options();
        opts.password = "right";
        opts.iterations = Crypto.MIN_ITERATIONS;

        String stego = Stego.hide("cover", "secret", opts).text;
        try {
            Stego.reveal(stego, "wrong");
            throw new AssertionError("a wrong password was accepted");
        } catch (StegoException e) {
            expect(e.kind == StegoException.Kind.WRONG_PASSWORD, "unexpected kind " + e.kind);
        }
    }

    private static void tamper() throws Exception {
        Stego.Options opts = new Stego.Options();
        opts.password = "pw";
        opts.iterations = Crypto.MIN_ITERATIONS;

        String stego = Stego.hide("cover", "secret message", opts).text;
        Stego.Scanned s = Stego.scan(stego);
        s.container.payload[s.container.payload.length / 2] ^= 0x01;

        try {
            Stego.unseal(s.container, "pw");
            throw new AssertionError("a flipped ciphertext bit was accepted");
        } catch (StegoException expected) {
            // correct
        }
    }

    private static void padding() throws Exception {
        int[] sizes = new int[3];
        int[] lengths = {1, 5, 9};

        for (int i = 0; i < lengths.length; i++) {
            StringBuilder sb = new StringBuilder();
            for (int k = 0; k < lengths[i]; k++) {
                sb.append('x');
            }
            Stego.Options opts = new Stego.Options();
            opts.password = "pw";
            opts.iterations = Crypto.MIN_ITERATIONS;

            String stego = Stego.hide("cover", sb.toString(), opts).text;
            sizes[i] = Stego.scan(stego).container.payload.length;
        }
        expect(sizes[0] == sizes[1] && sizes[1] == sizes[2],
                "payload sizes leak the message length: " + Arrays.toString(sizes));
    }

    private static void coverPreserved() throws Exception {
        String cover = "سلام دنیا!\nLine two.\tTabbed.";
        String stego = Stego.hide(cover, "hi", new Stego.Options()).text;
        expect(ZwCodec.strip(stego).equals(cover), "the cover text was modified");
    }

    private static void legacy() throws Exception {
        String secret = "legacy message";
        for (String prefix : new String[]{"STEGO_V1:", "STEGO_RAW:"}) {
            byte[] raw = (prefix + secret).getBytes(StandardCharsets.UTF_8);
            String stego = ZwCodec.inject("cover text", ZwCodec.encode(raw, ZwCodec.B2));
            String got = Stego.reveal(stego, null);
            expect(secret.equals(got), prefix + ": recovered \"" + got + "\"");
        }
    }

    /** The same vector selftest.go pins. Both sides must agree byte for byte. */
    private static void crossVector() throws Exception {
        byte[] salt = new byte[Crypto.SALT_LEN];
        Arrays.fill(salt, (byte) 0xA5);
        byte[] nonce = new byte[Crypto.NONCE_LEN];
        Arrays.fill(nonce, (byte) 0x5A);

        byte[] key = Crypto.deriveKey("Sayeh", salt, Crypto.MIN_ITERATIONS);
        byte[] sealed = Crypto.seal(key, nonce,
                "cross-implementation vector".getBytes(StandardCharsets.UTF_8),
                "ZWS3-AAD".getBytes(StandardCharsets.US_ASCII));
        Crypto.wipe(key);

        String got = hex(MessageDigest.getInstance("SHA-256").digest(sealed));
        String want = "83f9f35b42ce634a95c984aad7a48dbe9bed8c120114341464ee1b6405f72398";
        expect(got.equals(want), "sealed vector digest is " + got + ", want " + want);
    }

    // -----------------------------------------------------------------------

    /**
     * Resolves a password argument. A leading '@' means "read the first line
     * of this file" — the only reliable way to pass a non-ASCII password on a
     * Windows console without the code page mangling it.
     */
    private static String password(String arg) throws Exception {
        if (arg == null) {
            return "";
        }
        if (!arg.startsWith("@")) {
            return arg;
        }
        String s = new String(Files.readAllBytes(Paths.get(arg.substring(1))), StandardCharsets.UTF_8);
        int cut = s.indexOf('\r');
        if (cut < 0) {
            cut = s.indexOf('\n');
        }
        return cut < 0 ? s : s.substring(0, cut);
    }

    private static void cli(String[] args) throws Exception {
        switch (args[0]) {
            case "hide": {
                String secret = new String(Files.readAllBytes(Paths.get(args[1])), StandardCharsets.UTF_8);
                Stego.Options opts = new Stego.Options();
                opts.password = args.length > 3 ? password(args[3]) : "";
                opts.iterations = Crypto.MIN_ITERATIONS;
                String stego = Stego.hide("Cover.", secret, opts).text;
                Files.write(Paths.get(args[2]), stego.getBytes(StandardCharsets.UTF_8));
                System.out.println("wrote " + args[2]);
                break;
            }
            case "reveal": {
                String text = new String(Files.readAllBytes(Paths.get(args[1])), StandardCharsets.UTF_8);
                String secret = Stego.reveal(text, args.length > 2 ? password(args[2]) : "");
                // Write the result as UTF-8 bytes rather than printing it: the
                // Windows console code page would otherwise mangle Persian.
                Files.write(Paths.get(args.length > 3 ? args[3] : "revealed.txt"),
                        secret.getBytes(StandardCharsets.UTF_8));
                System.out.println("revealed " + secret.length() + " characters");
                break;
            }
            case "vector": {
                byte[] salt = new byte[Crypto.SALT_LEN];
                Arrays.fill(salt, (byte) 0xA5);
                byte[] nonce = new byte[Crypto.NONCE_LEN];
                Arrays.fill(nonce, (byte) 0x5A);
                byte[] key = Crypto.deriveKey("Sayeh", salt, Crypto.MIN_ITERATIONS);
                byte[] sealed = Crypto.seal(key, nonce,
                        "cross-implementation vector".getBytes(StandardCharsets.UTF_8),
                        "ZWS3-AAD".getBytes(StandardCharsets.US_ASCII));
                System.out.println(hex(MessageDigest.getInstance("SHA-256").digest(sealed)));
                break;
            }
            case "bench": {
                long start = System.nanoTime();
                Crypto.pbkdf2("benchmark password", new byte[16], Crypto.DEFAULT_ITERATIONS, 32);
                long ms = (System.nanoTime() - start) / 1_000_000;
                System.out.println("PBKDF2 x" + Crypto.DEFAULT_ITERATIONS + ": " + ms + " ms");
                break;
            }
            default:
                System.out.println("unknown command " + args[0]);
                System.exit(2);
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }
}
