package com.neo4j.tools.certtool.crypto;

import java.util.Arrays;
import java.util.Base64;

/**
 * RFC 7468 textual encoding of DER structures.
 *
 * <p>{@code PEMEncoder}/{@code PEMDecoder} (JEP 470) would be the obvious choice, but they do not
 * exist before JDK 25 and are only a preview API there — using them would both raise this tool's
 * baseline above JDK 21 and force {@code --enable-preview} on every user at compile and run time.
 * PEM is a base64 body between two label lines, so it is written directly here instead.
 */
public final class Pem {

    public static final String LABEL_CERTIFICATE = "CERTIFICATE";
    public static final String LABEL_PRIVATE_KEY = "PRIVATE KEY";
    public static final String LABEL_ENCRYPTED_PRIVATE_KEY = "ENCRYPTED PRIVATE KEY";

    /** RFC 7468 generators must wrap the base64 body at 64 characters. */
    private static final int LINE_LENGTH = 64;

    private Pem() {}

    public static String encode(String label, byte[] der) {
        String body = Base64.getMimeEncoder(LINE_LENGTH, new byte[] {'\n'}).encodeToString(der);
        return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
    }

    /**
     * Decodes the first block carrying {@code expectedLabel}.
     *
     * @throws IllegalArgumentException if no such block is present
     */
    public static byte[] decode(String pem, String expectedLabel) {
        String begin = "-----BEGIN " + expectedLabel + "-----";
        String end = "-----END " + expectedLabel + "-----";
        int start = pem.indexOf(begin);
        if (start < 0) {
            throw new IllegalArgumentException("No '" + expectedLabel + "' block found");
        }
        int bodyStart = start + begin.length();
        int bodyEnd = pem.indexOf(end, bodyStart);
        if (bodyEnd < 0) {
            throw new IllegalArgumentException("Unterminated '" + expectedLabel + "' block");
        }
        String body = pem.substring(bodyStart, bodyEnd).replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    /** Reports whether a PEM document contains a block with the given label. */
    public static boolean contains(String pem, String label) {
        return pem.contains("-----BEGIN " + label + "-----");
    }

    /**
     * Decodes the first block carrying {@code expectedLabel} from a document held as raw bytes,
     * zeroing the intermediate base64 body before returning.
     *
     * <p>The byte-level variants exist for documents holding private material: the caller can zero
     * the buffer it read the file into, and the base64 body assembled here, where the {@code String}
     * that {@link #decode(String, String)} runs against can never be cleared.
     *
     * @throws IllegalArgumentException if no such block is present
     */
    public static byte[] decode(byte[] document, String expectedLabel) {
        byte[] begin = bytes("-----BEGIN " + expectedLabel + "-----");
        byte[] end = bytes("-----END " + expectedLabel + "-----");
        int start = indexOf(document, begin, 0);
        if (start < 0) {
            throw new IllegalArgumentException("No '" + expectedLabel + "' block found");
        }
        int bodyStart = start + begin.length;
        int bodyEnd = indexOf(document, end, bodyStart);
        if (bodyEnd < 0) {
            throw new IllegalArgumentException("Unterminated '" + expectedLabel + "' block");
        }
        // Strip whitespace in place rather than through a String: the body of a private key block
        // is the key itself, lightly disguised.
        byte[] compact = new byte[bodyEnd - bodyStart];
        int length = 0;
        for (int i = bodyStart; i < bodyEnd; i++) {
            byte b = document[i];
            if (b != '\n' && b != '\r' && b != ' ' && b != '\t') {
                compact[length++] = b;
            }
        }
        try {
            return Base64.getDecoder().decode(Arrays.copyOf(compact, length));
        } finally {
            Arrays.fill(compact, 0, length, (byte) 0);
        }
    }

    /** Reports whether a document held as raw bytes contains a block with the given label. */
    public static boolean contains(byte[] document, String label) {
        return indexOf(document, bytes("-----BEGIN " + label + "-----"), 0) >= 0;
    }

    private static byte[] bytes(String text) {
        return text.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        if (needle.length == 0 || needle.length > haystack.length) {
            return needle.length == 0 ? from : -1;
        }
        outer:
        for (int i = from; i <= haystack.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }
}
