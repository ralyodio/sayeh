package ir.sayeh.stego;

/**
 * Zero-width carrier codecs. Mirrors codec.go byte for byte.
 *
 * <p>U+200C (ZERO WIDTH NON-JOINER) is deliberately never used: it is a
 * meaningful character in Persian/Arabic script (نیم‌فاصله), so carrying data
 * in it would corrupt the cover text.
 */
public final class ZwCodec {

    public static final char ZW_SPACE  = '​'; // ZERO WIDTH SPACE
    public static final char ZW_JOINER = '‍'; // ZERO WIDTH JOINER
    public static final char ZW_WORDJN = '⁠'; // WORD JOINER
    public static final char ZW_PLUS   = '⁤'; // INVISIBLE PLUS

    /** 2 bits per character over a 4-symbol alphabet. Default. */
    public static final int B4 = 4;
    /** 1 bit per character, ZWSP/ZWJ only. Widest compatibility. */
    public static final int B2 = 2;

    private static final char[] ALPHABET_B4 = {ZW_SPACE, ZW_JOINER, ZW_WORDJN, ZW_PLUS};
    private static final char[] ALPHABET_B2 = {ZW_JOINER, ZW_SPACE}; // index = bit value

    private ZwCodec() {
    }

    public static boolean isCarrier(char c) {
        return c == ZW_SPACE || c == ZW_JOINER || c == ZW_WORDJN || c == ZW_PLUS;
    }

    public static String name(int codec) {
        return codec == B4 ? "B4 (2 bits/char)" : "B2 (1 bit/char)";
    }

    /** Renders bytes as invisible characters, most significant bit first. */
    public static String encode(byte[] data, int codec) {
        StringBuilder sb = new StringBuilder(data.length * (codec == B4 ? 4 : 8));

        if (codec == B4) {
            for (byte b : data) {
                int v = b & 0xFF;
                sb.append(ALPHABET_B4[(v >>> 6) & 3]);
                sb.append(ALPHABET_B4[(v >>> 4) & 3]);
                sb.append(ALPHABET_B4[(v >>> 2) & 3]);
                sb.append(ALPHABET_B4[v & 3]);
            }
        } else {
            for (byte b : data) {
                int v = b & 0xFF;
                for (int i = 7; i >= 0; i--) {
                    sb.append(ALPHABET_B2[(v >>> i) & 1]);
                }
            }
        }
        return sb.toString();
    }

    /**
     * Reads invisible characters back into bytes. Characters outside the
     * codec's alphabet are skipped, so visible cover text is transparent.
     * Trailing bits that do not complete a byte are discarded.
     */
    public static byte[] decode(String text, int codec) {
        int n = text.length();
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(n / (codec == B4 ? 4 : 8) + 8);

        int acc = 0;
        int have = 0;

        for (int i = 0; i < n; i++) {
            char c = text.charAt(i);
            int sym;
            int width;

            if (codec == B4) {
                switch (c) {
                    case ZW_SPACE:  sym = 0; break;
                    case ZW_JOINER: sym = 1; break;
                    case ZW_WORDJN: sym = 2; break;
                    case ZW_PLUS:   sym = 3; break;
                    default: continue;
                }
                width = 2;
            } else {
                switch (c) {
                    case ZW_SPACE:  sym = 1; break;
                    case ZW_JOINER: sym = 0; break;
                    default: continue;
                }
                width = 1;
            }

            acc = (acc << width) | sym;
            have += width;
            if (have == 8) {
                out.write(acc & 0xFF);
                acc = 0;
                have = 0;
            }
        }
        return out.toByteArray();
    }

    /** Removes every carrier character from s. */
    public static String strip(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!isCarrier(c)) {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Counts the carrier characters in s. */
    public static int countCarriers(String s) {
        int n = 0;
        for (int i = 0; i < s.length(); i++) {
            if (isCarrier(s.charAt(i))) {
                n++;
            }
        }
        return n;
    }

    /**
     * Places the payload inside the cover text, right after its first visible
     * code point. Carriers already present in the cover are removed first, so
     * two payloads can never interleave.
     */
    public static String inject(String cover, String payload) {
        String clean = strip(cover);
        if (clean.isEmpty()) {
            return payload;
        }
        int split = clean.offsetByCodePoints(0, 1); // keep surrogate pairs intact
        return clean.substring(0, split) + payload + clean.substring(split);
    }
}
