package ir.sayeh.stego;

import java.io.ByteArrayOutputStream;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.crypto.AEADBadTagException;

/**
 * High-level hide/reveal API. Pure java.* and javax.* on purpose — no Android
 * imports — so the exact code that ships in the app can also be run and
 * verified on a desktop JVM (see SelfTest).
 */
public final class Stego {

    /** Options for hiding. */
    public static final class Options {
        public String password = "";     // empty means "do not encrypt"
        public int codec = ZwCodec.B4;
        public int iterations = Crypto.DEFAULT_ITERATIONS;
        public boolean noCompress = false;
    }

    /** What was produced or found, for display. */
    public static final class Report {
        public boolean encrypted;
        public boolean compressed;
        public int codec = ZwCodec.B4;
        public int iterations;
        public int secretSize;
        public int containerSize;
        public int carriers;
        public boolean legacy;

        public String describe() {
            StringBuilder sb = new StringBuilder();
            sb.append(encrypted
                    ? "AES-256-GCM, PBKDF2-SHA256 x" + iterations
                    : "not encrypted");
            if (compressed) {
                sb.append(" | DEFLATE");
            }
            sb.append(" | ").append(ZwCodec.name(codec));
            if (legacy) {
                sb.append(" | legacy v1/v2");
            }
            return sb.toString();
        }
    }

    /** A scan result: the sealed container plus what we can say about it. */
    public static final class Scanned {
        public Format.Container container; // null for a legacy payload
        public String legacySecret;        // non-null only for legacy payloads
        public Report report = new Report();

        public boolean needsPassword() {
            return container != null && container.isEncrypted();
        }
    }

    /** Hiding produces the stego text plus a report. */
    public static final class Hidden {
        public String text;
        public Report report = new Report();
    }

    private Stego() {
    }

    // -----------------------------------------------------------------------
    // Hide
    // -----------------------------------------------------------------------

    public static Hidden hide(String cover, String secret, Options opts)
            throws StegoException {

        if (secret == null || secret.isEmpty()) {
            throw new StegoException(StegoException.Kind.EMPTY_SECRET,
                    "The secret is empty — there is nothing to hide.");
        }
        if (cover == null) {
            cover = "";
        }

        byte[] body = secret.getBytes(StandardCharsets.UTF_8);

        Hidden result = new Hidden();
        result.report.codec = opts.codec;
        result.report.secretSize = body.length;

        // Compress before encrypting: it often shrinks natural language by
        // 3-5x, which matters when every byte costs four invisible characters.
        // Safe here because an attacker cannot inject chosen plaintext into
        // the secret, which is what makes compression-then-encryption risky
        // in protocols like TLS.
        if (!opts.noCompress) {
            byte[] squeezed = deflate(body);
            if (squeezed.length < body.length) {
                body = squeezed;
                result.report.compressed = true;
            }
        }

        Format.Container c = new Format.Container();
        if (result.report.compressed) {
            c.flags |= Format.FLAG_COMPRESSED;
        }

        try {
            if (opts.password == null || opts.password.isEmpty()) {
                c.payload = Format.packInner(body, false);
            } else {
                c.flags |= Format.FLAG_ENCRYPTED;
                c.kdf = Format.KDF_PBKDF2_SHA256;
                c.iterations = opts.iterations;
                c.salt = Crypto.random(Crypto.SALT_LEN);
                c.nonce = Crypto.random(Crypto.NONCE_LEN);

                byte[] inner = Format.packInner(body, true);
                byte[] key = Crypto.deriveKey(opts.password, c.salt, c.iterations);
                try {
                    byte[] aad = c.buildHeader(inner.length + Crypto.GCM_OVERHEAD);
                    c.payload = Crypto.seal(key, c.nonce, inner, aad);
                } finally {
                    Crypto.wipe(key);
                }

                result.report.encrypted = true;
                result.report.iterations = opts.iterations;
            }
        } catch (GeneralSecurityException e) {
            throw new StegoException(StegoException.Kind.CORRUPT,
                    "Encryption failed: " + e.getMessage());
        }

        byte[] raw = c.marshal();
        String invisible = ZwCodec.encode(raw, opts.codec);

        result.report.containerSize = raw.length;
        result.report.carriers = invisible.length();
        result.text = ZwCodec.inject(cover, invisible);
        return result;
    }

    // -----------------------------------------------------------------------
    // Scan / reveal
    // -----------------------------------------------------------------------

    /** Recovers and identifies a payload without decrypting it. */
    public static Scanned scan(String text) throws StegoException {
        if (text == null) {
            text = "";
        }

        StegoException structural = null;

        for (int codec : new int[]{ZwCodec.B4, ZwCodec.B2}) {
            byte[] raw = ZwCodec.decode(text, codec);
            if (raw.length == 0) {
                continue;
            }
            try {
                Format.Container c = Format.parse(raw);

                Scanned s = new Scanned();
                s.container = c;
                s.report.encrypted = c.isEncrypted();
                s.report.compressed = c.isCompressed();
                s.report.codec = codec;
                s.report.iterations = c.iterations;
                s.report.containerSize = c.header.length + c.payload.length;
                s.report.carriers = ZwCodec.countCarriers(text);
                return s;
            } catch (StegoException e) {
                // Only a magic mismatch means "wrong codec, keep looking".
                if (e.kind == StegoException.Kind.BAD_MAGIC
                        || e.kind == StegoException.Kind.NO_PAYLOAD) {
                    continue;
                }
                structural = e;
            }
        }
        if (structural != null) {
            throw structural;
        }

        String legacy = decodeLegacy(text);
        if (legacy != null) {
            Scanned s = new Scanned();
            s.legacySecret = legacy;
            s.report.legacy = true;
            s.report.codec = ZwCodec.B2;
            s.report.secretSize = legacy.getBytes(StandardCharsets.UTF_8).length;
            s.report.carriers = ZwCodec.countCarriers(text);
            return s;
        }

        if (ZwCodec.countCarriers(text) == 0) {
            throw StegoException.noPayload();
        }
        throw StegoException.badMagic();
    }

    /** Turns a scanned container into the original secret. */
    public static String unseal(Format.Container c, String password) throws StegoException {
        byte[] inner;

        if (c.isEncrypted()) {
            if (password == null || password.isEmpty()) {
                throw new StegoException(StegoException.Kind.NEEDS_PASSWORD,
                        "This payload is encrypted and needs a password.");
            }
            byte[] key = null;
            try {
                key = Crypto.deriveKey(password, c.salt, c.iterations);
                inner = Crypto.open(key, c.nonce, c.payload, c.header);
            } catch (AEADBadTagException e) {
                throw StegoException.wrongPassword();
            } catch (GeneralSecurityException e) {
                // Every other failure mode is also "it did not authenticate";
                // reporting them separately would leak which part went wrong.
                throw StegoException.wrongPassword();
            } finally {
                Crypto.wipe(key);
            }
        } else {
            inner = c.payload;
        }

        byte[] body = Format.unpackInner(inner);

        if (c.isCompressed()) {
            try {
                body = inflate(body);
            } catch (DataFormatException e) {
                throw new StegoException(StegoException.Kind.CORRUPT,
                        "The payload could not be decompressed.");
            }
        }
        return decodeUtf8(body);
    }

    /** Scan and unseal in one step. */
    public static String reveal(String text, String password) throws StegoException {
        Scanned s = scan(text);
        if (s.legacySecret != null) {
            return s.legacySecret;
        }
        return unseal(s.container, password);
    }

    /**
     * Reads the v1 ({@code STEGO_V1:}) and v2 ({@code STEGO_RAW:}) layouts so
     * older messages keep working. v2's encrypted form is not carried forward:
     * it derived its key with a bare SHA-256.
     */
    public static String decodeLegacy(String text) {
        byte[] raw = ZwCodec.decode(text, ZwCodec.B2);
        if (raw.length == 0) {
            return null;
        }
        for (String prefix : new String[]{"STEGO_V1:", "STEGO_RAW:"}) {
            byte[] p = prefix.getBytes(StandardCharsets.US_ASCII);
            if (Format.startsWith(raw, p)) {
                byte[] body = java.util.Arrays.copyOfRange(raw, p.length, raw.length);
                try {
                    return decodeUtf8(body);
                } catch (StegoException e) {
                    return null;
                }
            }
        }
        return null;
    }

    /** True when the text carries a v2 {@code STEGO_ENC:} payload. */
    public static boolean isLegacyEncrypted(String text) {
        byte[] raw = ZwCodec.decode(text, ZwCodec.B2);
        return Format.startsWith(raw, "STEGO_ENC:".getBytes(StandardCharsets.US_ASCII));
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private static String decodeUtf8(byte[] body) throws StegoException {
        CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            return decoder.decode(ByteBuffer.wrap(body)).toString();
        } catch (CharacterCodingException e) {
            throw new StegoException(StegoException.Kind.CORRUPT,
                    "The recovered data is not valid text.");
        }
    }

    static byte[] deflate(byte[] data) {
        Deflater d = new Deflater(Deflater.BEST_COMPRESSION, true); // nowrap: raw DEFLATE
        try {
            d.setInput(data);
            d.finish();
            ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);
            byte[] buf = new byte[4096];
            while (!d.finished()) {
                out.write(buf, 0, d.deflate(buf));
            }
            return out.toByteArray();
        } finally {
            d.end();
        }
    }

    static byte[] inflate(byte[] data) throws DataFormatException, StegoException {
        Inflater inf = new Inflater(true);
        try {
            inf.setInput(data);
            ByteArrayOutputStream out = new ByteArrayOutputStream(data.length * 4);
            byte[] buf = new byte[4096];
            while (!inf.finished()) {
                int n = inf.inflate(buf);
                if (n == 0 && (inf.needsInput() || inf.needsDictionary())) {
                    break; // truncated stream
                }
                out.write(buf, 0, n);
                // Bound the output so a hostile payload cannot be a zip bomb.
                if (out.size() > Format.MAX_PAYLOAD) {
                    throw new StegoException(StegoException.Kind.CORRUPT,
                            "Decompressed data exceeds the size limit.");
                }
            }
            return out.toByteArray();
        } finally {
            inf.end();
        }
    }
}
