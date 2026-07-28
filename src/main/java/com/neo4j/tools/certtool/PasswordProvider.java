package com.neo4j.tools.certtool;

import java.io.Console;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Supplies the passwords that private keys are encrypted with.
 *
 * <p>A password is issued per <em>subject</em> — a node name, or {@code ca}/{@code intermediate}
 * for authority keys — and cached, so all of a node's scope keys share one password while
 * different nodes get different ones. Passwords are held as {@code char[]} and zeroed on
 * {@link #close()} rather than being interned as immutable strings.
 *
 * <p>A password is never accepted as a command line argument: arguments are visible to any user on
 * the machine through {@code ps} and are recorded in shell history.
 */
public final class PasswordProvider implements AutoCloseable {

    /** Where passwords come from. */
    public enum Mode {
        /** Read from the terminal with echo disabled. */
        PROMPT,
        /** Read from a file, either one password per subject or a single password for all. */
        FILE,
        /** Generated randomly and reported once at the end of the run. */
        GENERATE
    }

    /** Key used in a password file to supply one password for every subject. */
    private static final String WILDCARD = "*";

    /**
     * Minimum length for a password typed at the prompt. Short enough not to be obstructive, long
     * enough that PBKDF2 is doing meaningful work rather than covering for a two-word password.
     */
    static final int MINIMUM_PROMPTED_LENGTH = 12;

    /** Entropy of a generated password, in bytes, before base64url encoding. */
    private static final int GENERATED_ENTROPY_BYTES = 24;

    private final Mode mode;
    private final boolean shared;
    private final Map<String, char[]> fromFile;
    private final SecureRandom random;
    private final Console console;
    private final Map<String, char[]> issued = new LinkedHashMap<>();

    private PasswordProvider(
            Mode mode,
            boolean shared,
            Map<String, char[]> fromFile,
            SecureRandom random,
            Console console) {
        this.mode = mode;
        this.shared = shared;
        this.fromFile = fromFile;
        this.random = random;
        this.console = console;
    }

    public static PasswordProvider prompting(boolean shared, SecureRandom random) {
        return new PasswordProvider(Mode.PROMPT, shared, Map.of(), random, System.console());
    }

    public static PasswordProvider generating(SecureRandom random) {
        return new PasswordProvider(Mode.GENERATE, false, Map.of(), random, null);
    }

    /**
     * Reads passwords from a file.
     *
     * <p>The file may hold a single password on its own line, used for every subject, or
     * {@code subject=password} lines to give each node its own. Lines starting with {@code #} are
     * ignored.
     */
    public static PasswordProvider fromFile(Path file, SecureRandom random) throws IOException {
        warnIfReadableByOthers(file);

        // Read as bytes and decode into char[] by hand. Files.readAllLines would put every
        // password into an immutable String, which cannot be zeroed and would sit on the heap for
        // the rest of the run.
        byte[] raw = Files.readAllBytes(file);
        Map<String, char[]> passwords = new LinkedHashMap<>();
        List<char[]> bareLines = new ArrayList<>();
        try {
            for (char[] line : splitLines(raw)) {
                try {
                    int from = 0;
                    int to = line.length;
                    while (from < to && Character.isWhitespace(line[from])) {
                        from++;
                    }
                    while (to > from && Character.isWhitespace(line[to - 1])) {
                        to--;
                    }
                    if (from == to || line[from] == '#') {
                        continue;
                    }
                    int separator = indexOf(line, '=', from, to);
                    if (separator > from) {
                        // The subject name is not a secret, so a String is fine for it.
                        String subject = new String(line, from, separator - from).strip();
                        passwords.put(subject, Arrays.copyOfRange(line, separator + 1, to));
                    } else {
                        bareLines.add(Arrays.copyOfRange(line, from, to));
                    }
                } finally {
                    Arrays.fill(line, '\0');
                }
            }
        } finally {
            Arrays.fill(raw, (byte) 0);
        }

        if (!bareLines.isEmpty()) {
            if (!passwords.isEmpty() || bareLines.size() > 1) {
                bareLines.forEach(line -> Arrays.fill(line, '\0'));
                passwords.values().forEach(password -> Arrays.fill(password, '\0'));
                throw new IOException(
                        file
                                + ": use either a single password on one line, or one "
                                + "'subject=password' line per node, but not both");
            }
            passwords.put(WILDCARD, bareLines.getFirst());
        }
        if (passwords.isEmpty()) {
            throw new IOException(file + ": no password found");
        }
        warnIfWeak(file, passwords);
        return new PasswordProvider(Mode.FILE, false, passwords, random, null);
    }

    /**
     * Decodes UTF-8 bytes and splits on line breaks without creating any {@link String}.
     *
     * <p>The decoded buffer is zeroed before returning, so the only remaining copies are the
     * per-line arrays handed back to the caller.
     */
    private static List<char[]> splitLines(byte[] raw) {
        java.nio.CharBuffer decoded = StandardCharsets.UTF_8.decode(java.nio.ByteBuffer.wrap(raw));
        char[] all = new char[decoded.remaining()];
        decoded.get(all);
        try {
            List<char[]> lines = new ArrayList<>();
            int start = 0;
            for (int i = 0; i <= all.length; i++) {
                boolean end = i == all.length;
                if (end || all[i] == '\n' || all[i] == '\r') {
                    if (i > start) {
                        lines.add(Arrays.copyOfRange(all, start, i));
                    }
                    start = i + 1;
                }
            }
            return lines;
        } finally {
            Arrays.fill(all, '\0');
        }
    }

    private static int indexOf(char[] line, char needle, int from, int to) {
        for (int i = from; i < to; i++) {
            if (line[i] == needle) {
                return i;
            }
        }
        return -1;
    }

    /**
     * Warns about file-supplied passwords short enough to be worth guessing offline. The prompt
     * enforces a minimum; a file cannot be rejected outright without breaking existing automation.
     */
    private static void warnIfWeak(Path file, Map<String, char[]> passwords) {
        long weak = passwords.values().stream()
                .filter(password -> password.length < MINIMUM_PROMPTED_LENGTH)
                .count();
        if (weak > 0) {
            System.err.printf(
                    "Warning: %s contains %d password(s) shorter than %d characters. "
                            + "Key encryption is only as strong as the password behind it.%n",
                    file, weak, MINIMUM_PROMPTED_LENGTH);
        }
    }

    private static void warnIfReadableByOthers(Path file) {
        try {
            var permissions = Files.getPosixFilePermissions(file);
            boolean exposed = permissions.stream()
                    .anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"));
            if (exposed) {
                System.err.println(
                        "Warning: " + file + " is readable beyond its owner. Consider: chmod 600 " + file);
            }
        } catch (UnsupportedOperationException | IOException notPosix) {
            // Windows, or an unreadable attribute view: nothing useful to check.
        }
    }

    public Mode mode() {
        return mode;
    }

    /**
     * Returns the password for a subject, reading or generating it on first use.
     *
     * <p>The returned array is owned by this provider and must not be mutated or cleared by the
     * caller; it stays valid until {@link #close()}.
     */
    public char[] forSubject(String subject) {
        String key = shared ? WILDCARD : subject;
        char[] cached = issued.get(key);
        if (cached != null) {
            return cached;
        }
        char[] password = switch (mode) {
            case PROMPT -> prompt(subject);
            case GENERATE -> generate();
            case FILE -> lookUp(subject);
        };
        issued.put(key, password);
        return password;
    }

    private char[] lookUp(String subject) {
        char[] password = fromFile.get(subject);
        if (password == null) {
            password = fromFile.get(WILDCARD);
        }
        if (password == null) {
            throw new IllegalStateException(
                    "The password file has no entry for '" + subject + "' and no default line");
        }
        return password;
    }

    private char[] generate() {
        byte[] entropy = new byte[GENERATED_ENTROPY_BYTES];
        random.nextBytes(entropy);
        // base64url without padding: only characters that are safe to paste into neo4j.conf.
        // Encoded to bytes rather than through encodeToString, so the password never exists as an
        // immutable String that cannot be zeroed afterwards.
        byte[] encoded = Base64.getUrlEncoder().withoutPadding().encode(entropy);
        try {
            char[] password = new char[encoded.length];
            for (int i = 0; i < encoded.length; i++) {
                // base64url output is ASCII, so the byte value is the character value.
                password[i] = (char) (encoded[i] & 0xFF);
            }
            return password;
        } finally {
            Arrays.fill(entropy, (byte) 0);
            Arrays.fill(encoded, (byte) 0);
        }
    }

    private char[] prompt(String subject) {
        if (console == null || !console.isTerminal()) {
            throw new IllegalStateException(
                    """
                    No terminal is available to prompt for a password.
                    Use --password-file <path> or --generate-password when running non-interactively.""");
        }
        String what = shared ? "all private keys" : "the private keys of '" + subject + "'";
        while (true) {
            char[] first = console.readPassword("Password for %s: ", what);
            if (first == null) {
                throw new IllegalStateException("No password supplied (end of input)");
            }
            if (first.length < MINIMUM_PROMPTED_LENGTH) {
                Arrays.fill(first, '\0');
                console.printf(
                        "Password must be at least %d characters.%n", MINIMUM_PROMPTED_LENGTH);
                continue;
            }
            char[] second = console.readPassword("Confirm password for %s: ", what);
            if (second != null && Arrays.equals(first, second)) {
                Arrays.fill(second, '\0');
                return first;
            }
            Arrays.fill(first, '\0');
            if (second != null) {
                Arrays.fill(second, '\0');
            }
            console.printf("Passwords did not match, try again.%n");
        }
    }

    /**
     * The passwords handed out so far, for the run summary.
     *
     * <p>Only populated for {@link Mode#GENERATE}: a password the user chose or supplied in a file
     * is theirs to keep, and echoing it back would only put it somewhere new.
     */
    public Map<String, char[]> generatedPasswords() {
        return mode == Mode.GENERATE ? Collections.unmodifiableMap(issued) : Map.of();
    }

    /** Zeroes every password this provider is holding. */
    @Override
    public void close() {
        issued.values().forEach(password -> Arrays.fill(password, '\0'));
        issued.clear();
        fromFile.values().forEach(password -> Arrays.fill(password, '\0'));
    }

    /** Reads a single password from a file, used when unlocking an existing CA key. */
    public static char[] readSingleFrom(Path file) throws IOException {
        warnIfReadableByOthers(file);
        byte[] raw = Files.readAllBytes(file);
        try {
            for (char[] line : splitLines(raw)) {
                int from = 0;
                int to = line.length;
                while (from < to && Character.isWhitespace(line[from])) {
                    from++;
                }
                while (to > from && Character.isWhitespace(line[to - 1])) {
                    to--;
                }
                if (from < to && line[from] != '#') {
                    char[] password = Arrays.copyOfRange(line, from, to);
                    Arrays.fill(line, '\0');
                    return password;
                }
                Arrays.fill(line, '\0');
            }
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
        throw new IOException(file + ": no password found");
    }
}
