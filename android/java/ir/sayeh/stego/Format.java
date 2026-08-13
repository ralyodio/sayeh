package ir.sayeh.stego;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;

/** Wire format v3 ("ZWS3"). Mirrors format.go — see SPEC.md. */
public final class Format {

    public static final byte[] MAGIC = {'Z', 'W', 'S', '3'};
    public static final byte VERSION = 3;

    public static final int FLAG_ENCRYPTED = 1;
    public static final int FLAG_COMPRESSED = 2;

    public static final int KDF_NONE = 0;
    public static final int KDF_PBKDF2_SHA256 = 1;

    public static final int HEADER_FIXED = 8; // magic + version + flags + kdf + reserved
    public static final int LEN_FIELD = 4;
    public static final int PAD_BLOCK = 64;
    public static final int MAX_PAYLOAD = 16 << 20;

    private Format() {
    }

    /** A parsed, still-sealed payload. */
    public static final class Container {
        public int flags;
        public int kdf;
        public int iterations;
        public byte[] salt;
        public byte[] nonce;
        public byte[] payload;
        /** Every byte before the payload, including the length field. Used as GCM AAD. */
        public byte[] header;

        public boolean isEncrypted() {
            return (flags & FLAG_ENCRYPTED) != 0;
        }

        public boolean isCompressed() {
            return (flags & FLAG_COMPRESSED) != 0;
        }

        /**
         * Builds the header for a given payload length. It is authenticated as
         * AAD, so version, flags, KDF id, iteration count, salt, nonce and
         * length can none of them be edited without breaking the tag.
         */
        public byte[] buildHeader(int payloadLen) {
            ByteArrayOutputStream out = new ByteArrayOutputStream(64);
            out.write(MAGIC, 0, MAGIC.length);
            out.write(VERSION);
            out.write(flags);
            out.write(kdf);
            out.write(0); // reserved

            if (isEncrypted()) {
                writeInt(out, iterations);
                out.write(salt, 0, salt.length);
                out.write(nonce, 0, nonce.length);
            }
            writeInt(out, payloadLen);
            return out.toByteArray();
        }

        public byte[] marshal() {
            byte[] h = buildHeader(payload.length);
            byte[] all = new byte[h.length + payload.length];
            System.arraycopy(h, 0, all, 0, h.length);
            System.arraycopy(payload, 0, all, h.length, payload.length);
            return all;
        }
    }

    private static void writeInt(ByteArrayOutputStream out, int v) {
        out.write((v >>> 24) & 0xFF);
        out.write((v >>> 16) & 0xFF);
        out.write((v >>> 8) & 0xFF);
        out.write(v & 0xFF);
    }

    /** Validates and splits raw bytes recovered from the carriers. */
    public static Container parse(byte[] raw) throws StegoException {
        if (raw.length == 0) {
            throw StegoException.noPayload();
        }
        if (raw.length < HEADER_FIXED + LEN_FIELD || !startsWith(raw, MAGIC)) {
            throw StegoException.badMagic();
        }
        if (raw[4] != VERSION) {
            throw new StegoException(StegoException.Kind.BAD_VERSION,
                    "This payload was made by a newer version of Sayeh.");
        }

        Container c = new Container();
        c.flags = raw[5] & 0xFF;
        c.kdf = raw[6] & 0xFF;
        int off = HEADER_FIXED;

        if (c.isEncrypted()) {
            int need = off + 4 + Crypto.SALT_LEN + Crypto.NONCE_LEN + LEN_FIELD;
            if (raw.length < need) {
                throw StegoException.truncated();
            }
            if (c.kdf != KDF_PBKDF2_SHA256) {
                throw new StegoException(StegoException.Kind.CORRUPT,
                        "Unsupported key derivation function id " + c.kdf + ".");
            }
            c.iterations = ByteBuffer.wrap(raw, off, 4).getInt();
            off += 4;
            c.salt = Arrays.copyOfRange(raw, off, off + Crypto.SALT_LEN);
            off += Crypto.SALT_LEN;
            c.nonce = Arrays.copyOfRange(raw, off, off + Crypto.NONCE_LEN);
            off += Crypto.NONCE_LEN;

            if (Integer.compareUnsigned(c.iterations, Crypto.MIN_ITERATIONS) < 0) {
                throw new StegoException(StegoException.Kind.CORRUPT,
                        "Refusing this payload: its iteration count is below the safe minimum.");
            }
        } else if (c.kdf != KDF_NONE) {
            throw StegoException.badMagic();
        }

        if (raw.length < off + LEN_FIELD) {
            throw StegoException.truncated();
        }
        int n = ByteBuffer.wrap(raw, off, 4).getInt();
        off += LEN_FIELD;

        if (n < 0 || n > MAX_PAYLOAD) {
            throw new StegoException(StegoException.Kind.CORRUPT,
                    "The declared payload size is out of range.");
        }
        if (raw.length - off < n) {
            throw StegoException.truncated();
        }

        c.header = Arrays.copyOfRange(raw, 0, off);
        c.payload = Arrays.copyOfRange(raw, off, off + n);
        return c;
    }

    /** Builds bodyLen || body || padding. */
    public static byte[] packInner(byte[] body, boolean pad) {
        int total = LEN_FIELD + body.length;
        if (pad) {
            total = (total + PAD_BLOCK - 1) / PAD_BLOCK * PAD_BLOCK;
        }

        byte[] inner = new byte[total];
        inner[0] = (byte) (body.length >>> 24);
        inner[1] = (byte) (body.length >>> 16);
        inner[2] = (byte) (body.length >>> 8);
        inner[3] = (byte) body.length;
        System.arraycopy(body, 0, inner, LEN_FIELD, body.length);

        int padLen = total - LEN_FIELD - body.length;
        if (padLen > 0) {
            byte[] noise = Crypto.random(padLen);
            System.arraycopy(noise, 0, inner, LEN_FIELD + body.length, padLen);
        }
        return inner;
    }

    /** Reverses {@link #packInner} and drops the padding. */
    public static byte[] unpackInner(byte[] inner) throws StegoException {
        if (inner.length < LEN_FIELD) {
            throw StegoException.truncated();
        }
        int n = ByteBuffer.wrap(inner, 0, 4).getInt();
        if (n < 0 || n > inner.length - LEN_FIELD) {
            throw StegoException.truncated();
        }
        return Arrays.copyOfRange(inner, LEN_FIELD, LEN_FIELD + n);
    }

    static boolean startsWith(byte[] data, byte[] prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }
}
