package com.neo4j.tools.certtool.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;

/** Checks the PEM encoding against RFC 7468's requirements. */
class PemTest {

    @Test
    void roundTripsArbitraryContent() {
        SecureRandom random = new SecureRandom();
        for (int length : new int[] {0, 1, 47, 48, 49, 100, 1000, 4096}) {
            byte[] der = new byte[length];
            random.nextBytes(der);
            String pem = Pem.encode(Pem.LABEL_CERTIFICATE, der);
            assertArrayEquals(der, Pem.decode(pem, Pem.LABEL_CERTIFICATE), "length " + length);
        }
    }

    @Test
    void wrapsTheBodyAtSixtyFourCharacters() {
        byte[] der = new byte[500];
        String pem = Pem.encode(Pem.LABEL_CERTIFICATE, der);

        String[] lines = pem.split("\n");
        assertEquals("-----BEGIN CERTIFICATE-----", lines[0]);
        assertEquals("-----END CERTIFICATE-----", lines[lines.length - 1]);
        for (int i = 1; i < lines.length - 1; i++) {
            assertTrue(lines[i].length() <= 64, "line " + i + " is " + lines[i].length() + " characters");
        }
    }

    @Test
    void endsWithANewlineSoBlocksConcatenateCleanly() {
        // public.crt holds a chain, written by appending one encoding after another.
        String first = Pem.encode(Pem.LABEL_CERTIFICATE, new byte[10]);
        String second = Pem.encode(Pem.LABEL_CERTIFICATE, new byte[20]);
        assertTrue(first.endsWith("\n"));
        String chain = first + second;
        assertTrue(chain.contains("-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----"));
    }

    @Test
    void decodesTheFirstBlockWithAMatchingLabel() {
        String document =
                Pem.encode(Pem.LABEL_CERTIFICATE, new byte[] {1, 2, 3})
                        + Pem.encode(Pem.LABEL_ENCRYPTED_PRIVATE_KEY, new byte[] {4, 5, 6});

        assertArrayEquals(new byte[] {1, 2, 3}, Pem.decode(document, Pem.LABEL_CERTIFICATE));
        assertArrayEquals(
                new byte[] {4, 5, 6}, Pem.decode(document, Pem.LABEL_ENCRYPTED_PRIVATE_KEY));
    }

    @Test
    void toleratesCarriageReturnsAndSurroundingText() {
        // Files that have been through a Windows editor, or that carry a human-readable preamble.
        String pem = Pem.encode(Pem.LABEL_CERTIFICATE, new byte[] {9, 8, 7}).replace("\n", "\r\n");
        String document = "Issued to core1\n" + pem + "\ntrailing notes\n";
        assertArrayEquals(new byte[] {9, 8, 7}, Pem.decode(document, Pem.LABEL_CERTIFICATE));
    }

    @Test
    void reportsAMissingBlock() {
        String document = Pem.encode(Pem.LABEL_CERTIFICATE, new byte[] {1});
        assertThrows(
                IllegalArgumentException.class,
                () -> Pem.decode(document, Pem.LABEL_ENCRYPTED_PRIVATE_KEY));
    }

    @Test
    void reportsAnUnterminatedBlock() {
        String document = "-----BEGIN CERTIFICATE-----\nAQID\n";
        assertThrows(
                IllegalArgumentException.class, () -> Pem.decode(document, Pem.LABEL_CERTIFICATE));
    }

    @Test
    void detectsWhichLabelsArePresent() {
        String document = Pem.encode(Pem.LABEL_ENCRYPTED_PRIVATE_KEY, new byte[] {1});
        assertTrue(Pem.contains(document, Pem.LABEL_ENCRYPTED_PRIVATE_KEY));
        assertFalse(Pem.contains(document, Pem.LABEL_PRIVATE_KEY));
        assertFalse(Pem.contains(document, Pem.LABEL_CERTIFICATE));
    }
}
