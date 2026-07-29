package com.neo4j.tools.certtool.crypto;

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
}
