package ir.sayeh.stego;

/** A failure the user is meant to read, with enough structure to react to. */
public class StegoException extends Exception {

    public enum Kind {
        NO_PAYLOAD,
        BAD_MAGIC,
        TRUNCATED,
        BAD_VERSION,
        NEEDS_PASSWORD,
        WRONG_PASSWORD,
        CORRUPT,
        EMPTY_SECRET
    }

    public final Kind kind;

    public StegoException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public static StegoException noPayload() {
        return new StegoException(Kind.NO_PAYLOAD, "No hidden data found in this text.");
    }

    public static StegoException badMagic() {
        return new StegoException(Kind.BAD_MAGIC,
                "Invisible characters were found, but they are not a Sayeh payload "
                        + "(truncated, reformatted, or produced by another tool).");
    }

    public static StegoException truncated() {
        return new StegoException(Kind.TRUNCATED,
                "The payload is truncated — the text was cut off or reformatted in transit.");
    }

    public static StegoException wrongPassword() {
        return new StegoException(Kind.WRONG_PASSWORD,
                "Decryption failed: wrong password, or the payload was altered.");
    }
}
