package com.neo4j.tools.certtool.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.HexFormat;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Checks the DER encoder against known-good encodings.
 *
 * <p>Everything else in the tool is built on these bytes, so the expected values here are written
 * out by hand from X.690 rather than captured from the implementation.
 */
class DerTest {

    private static final HexFormat HEX = HexFormat.of();

    @Nested
    @DisplayName("length encoding")
    class Lengths {

        @Test
        void shortFormForUpTo127Bytes() {
            assertEquals("0400", HEX.formatHex(Der.octetString(new byte[0])));
            assertEquals("04017f", HEX.formatHex(Der.octetString(new byte[] {0x7F})));
            assertEquals("047f" + "00".repeat(127), HEX.formatHex(Der.octetString(new byte[127])));
        }

        @Test
        void longFormFrom128Bytes() {
            // 0x81 says "one length octet follows", then the length itself.
            assertTrue(HEX.formatHex(Der.octetString(new byte[128])).startsWith("048180"));
            assertTrue(HEX.formatHex(Der.octetString(new byte[255])).startsWith("0481ff"));
            // 0x82 says "two length octets follow".
            assertTrue(HEX.formatHex(Der.octetString(new byte[256])).startsWith("04820100"));
            assertTrue(HEX.formatHex(Der.octetString(new byte[65535])).startsWith("0482ffff"));
            assertTrue(HEX.formatHex(Der.octetString(new byte[65536])).startsWith("0483010000"));
        }

        @Test
        void lengthsRoundTripThroughTheReader() {
            for (int size : new int[] {0, 1, 127, 128, 255, 256, 1000, 65535, 65536}) {
                byte[] encoded = Der.octetString(new byte[size]);
                byte[] decoded = new Der.Reader(encoded).readPrimitive(Der.TAG_OCTET_STRING);
                assertEquals(size, decoded.length, "round trip at size " + size);
            }
        }
    }

    @Nested
    @DisplayName("object identifiers")
    class Oid {

        @ParameterizedTest
        @CsvSource({
            // Known encodings from X.690 and RFC 5280.
            "2.5.4.3, 0603550403",
            "2.5.29.17, 0603551d11",
            "1.2.840.113549.1.1.11, 06092a864886f70d01010b",
            "1.2.840.10045.4.3.2, 06082a8648ce3d040302",
            "1.3.6.1.5.5.7.3.1, 06082b06010505070301",
            "1.2.840.113549.1.5.13, 06092a864886f70d01050d",
            "0.0, 060100",
            "2.100.3, 0603813403"
        })
        void encodesKnownOids(String dotted, String expectedHex) {
            assertEquals(expectedHex, HEX.formatHex(Der.oid(dotted)));
        }

        @ParameterizedTest
        @ValueSource(
                strings = {
                    "2.5.4.3",
                    "1.2.840.113549.1.1.11",
                    "1.3.6.1.5.5.7.3.2",
                    "2.16.840.1.101.3.4.1.42",
                    "0.39",
                    "1.39",
                    "2.999999"
                })
        void roundTripsThroughDecode(String dotted) {
            byte[] content = new Der.Reader(Der.oid(dotted)).readPrimitive(Der.TAG_OID);
            assertEquals(dotted, Der.decodeOid(content));
        }

        @Test
        void rejectsAnInvalidFirstArc() {
            assertThrows(IllegalArgumentException.class, () -> Der.oid("3.1.1"));
        }

        @Test
        void rejectsASingleArc() {
            assertThrows(IllegalArgumentException.class, () -> Der.oid("1"));
        }

        @Test
        void rejectsATruncatedEncoding() {
            // A trailing octet with the continuation bit set has no terminating octet.
            assertThrows(
                    IllegalArgumentException.class,
                    () -> Der.decodeOid(new byte[] {0x2A, (byte) 0x86}));
        }
    }

    @Nested
    @DisplayName("primitives")
    class Primitives {

        @Test
        void booleanTrueIsAllOnes() {
            // DER requires 0xFF for TRUE, not merely a non-zero value.
            assertEquals("0101ff", HEX.formatHex(Der.bool(true)));
            assertEquals("010100", HEX.formatHex(Der.bool(false)));
        }

        @Test
        void integersUseMinimalTwosComplement() {
            assertEquals("020100", HEX.formatHex(Der.integer(0)));
            assertEquals("020102", HEX.formatHex(Der.integer(2)));
            assertEquals("02017f", HEX.formatHex(Der.integer(127)));
            // 128 needs a leading zero octet so it is not read as negative.
            assertEquals("02020080", HEX.formatHex(Der.integer(128)));
            assertEquals("020200ff", HEX.formatHex(Der.integer(255)));
            assertEquals("0203010001", HEX.formatHex(Der.integer(65537)));
        }

        @Test
        void largeSerialNumbersSurviveEncoding() {
            BigInteger serial = new BigInteger("7b8d60e25fa688d0c422cd9159cae774", 16);
            byte[] encoded = Der.integer(serial);
            byte[] content = new Der.Reader(encoded).readPrimitive(Der.TAG_INTEGER);
            assertEquals(serial, new BigInteger(content));
        }

        @Test
        void bitStringRecordsUnusedBits() {
            assertEquals("03020780", HEX.formatHex(Der.bitString(new byte[] {(byte) 0x80}, 7)));
            assertEquals("030200ff", HEX.formatHex(Der.bitString(new byte[] {(byte) 0xFF}, 0)));
        }

        @Test
        void bitStringRejectsAnImpossibleUnusedBitCount() {
            assertThrows(
                    IllegalArgumentException.class, () -> Der.bitString(new byte[] {0x00}, 8));
            assertThrows(
                    IllegalArgumentException.class, () -> Der.bitString(new byte[] {0x00}, -1));
        }

        @Test
        void nullIsEmpty() {
            assertEquals("0500", HEX.formatHex(Der.nul()));
        }

        @Test
        void printableStringRejectsCharactersOutsideItsRepertoire() {
            assertEquals("13024742", HEX.formatHex(Der.printableString("GB")));
            // '@' and '_' are not in the PrintableString repertoire.
            assertThrows(IllegalArgumentException.class, () -> Der.printableString("a@b"));
            assertThrows(IllegalArgumentException.class, () -> Der.printableString("a_b"));
        }

        @Test
        void utf8StringCarriesNonAsciiText() {
            byte[] encoded = Der.utf8String("Zürich");
            byte[] content = new Der.Reader(encoded).readPrimitive(Der.TAG_UTF8_STRING);
            assertEquals("Zürich", new String(content, java.nio.charset.StandardCharsets.UTF_8));
        }

        @Test
        void ia5StringRejectsNonAscii() {
            assertThrows(IllegalArgumentException.class, () -> Der.ia5String("cörex.example.com"));
        }

        @Test
        void explicitTaggingUsesTheConstructedContextClass() {
            // [0] EXPLICIT wrapping INTEGER 2, as in the X.509 version field.
            assertEquals("a003020102", HEX.formatHex(Der.explicit(0, Der.integer(2))));
            assertEquals("a303020102", HEX.formatHex(Der.explicit(3, Der.integer(2))));
        }

        @Test
        void contextPrimitiveTaggingIsUsedForGeneralNames() {
            // dNSName is [2] IMPLICIT IA5String: the tag replaces the IA5String tag, so the
            // content is the bare ASCII with no nested tag of its own.
            byte[] encoded =
                    Der.contextPrimitive(2, "a.example".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            assertEquals("8209" + HEX.formatHex("a.example".getBytes(java.nio.charset.StandardCharsets.US_ASCII)),
                    HEX.formatHex(encoded));
        }
    }

    @Nested
    @DisplayName("time")
    class Times {

        @Test
        void usesUtcTimeBefore2050() {
            byte[] encoded = Der.time(Instant.parse("2026-07-28T12:34:56Z"));
            assertEquals(Der.TAG_UTC_TIME, encoded[0] & 0xFF);
            assertEquals(
                    "260728123456Z",
                    new String(
                            new Der.Reader(encoded).readPrimitive(Der.TAG_UTC_TIME),
                            java.nio.charset.StandardCharsets.US_ASCII));
        }

        @Test
        void usesGeneralizedTimeFrom2050() {
            // RFC 5280 switches representation at 2050, and a 10-year CA issued in 2041 crosses it.
            byte[] encoded = Der.time(Instant.parse("2050-01-01T00:00:00Z"));
            assertEquals(Der.TAG_GENERALIZED_TIME, encoded[0] & 0xFF);
            assertEquals(
                    "20500101000000Z",
                    new String(
                            new Der.Reader(encoded).readPrimitive(Der.TAG_GENERALIZED_TIME),
                            java.nio.charset.StandardCharsets.US_ASCII));
        }
    }

    @Nested
    @DisplayName("reader")
    class Reader {

        @Test
        void skipElementLandsOnTheNextElement() {
            // Regression test: a compound assignment that consumed the length twice made the
            // cursor land inside the skipped element instead of after it.
            byte[] document = Der.sequence(Der.integer(1), Der.octetString(new byte[200]), Der.bool(true));
            Der.Reader reader = new Der.Reader(document).readConstructed(Der.TAG_SEQUENCE);
            reader.skipElement();
            reader.skipElement();
            assertArrayEquals(new byte[] {(byte) 0xFF}, reader.readPrimitive(Der.TAG_BOOLEAN));
            assertTrue(!reader.hasNext());
        }

        @Test
        void skipElementHandlesLongFormLengths() {
            byte[] document = Der.sequence(Der.octetString(new byte[70000]), Der.integer(42));
            Der.Reader reader = new Der.Reader(document).readConstructed(Der.TAG_SEQUENCE);
            reader.skipElement();
            assertEquals(42, new BigInteger(reader.readPrimitive(Der.TAG_INTEGER)).intValue());
        }

        @Test
        void rejectsAnUnexpectedTag() {
            byte[] document = Der.sequence(Der.integer(1));
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new Der.Reader(document).readPrimitive(Der.TAG_OCTET_STRING));
        }

        @Test
        void rejectsTruncatedInput() {
            byte[] truncated = {0x30, 0x10, 0x02, 0x01};
            assertThrows(
                    IllegalArgumentException.class,
                    () -> new Der.Reader(truncated).readConstructed(Der.TAG_SEQUENCE).skipElement());
        }

        @Test
        void rejectsAnElementThatOverrunsItsParent() {
            // Inner element claims 16 bytes inside a 3-byte sequence.
            byte[] malformed = {0x30, 0x03, 0x04, 0x10, 0x00};
            Der.Reader outer = new Der.Reader(malformed).readConstructed(Der.TAG_SEQUENCE);
            assertThrows(IllegalArgumentException.class, () -> outer.readPrimitive(Der.TAG_OCTET_STRING));
        }
    }

    @Nested
    @DisplayName("subject public key extraction")
    class SubjectPublicKey {

        @Test
        void matchesTheJdkKeyIdentifierForAnEcKey() throws Exception {
            var generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec("secp256r1"));
            assertKeyIdentifierIsSha1OfKeyBits(generator.generateKeyPair().getPublic());
        }

        @Test
        void matchesTheJdkKeyIdentifierForAnRsaKey() throws Exception {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            assertKeyIdentifierIsSha1OfKeyBits(generator.generateKeyPair().getPublic());
        }

        private void assertKeyIdentifierIsSha1OfKeyBits(PublicKey publicKey) throws Exception {
            byte[] bits = Der.subjectPublicKeyBits(publicKey.getEncoded());
            byte[] expected = MessageDigest.getInstance("SHA-1").digest(bits);
            assertArrayEquals(expected, Extensions.keyIdentifier(publicKey));
            assertEquals(20, expected.length);
        }

        @Test
        void rejectsSomethingThatIsNotASubjectPublicKeyInfo() {
            byte[] notASpki = Der.sequence(Der.integer(1), Der.integer(2));
            assertThrows(
                    IllegalArgumentException.class, () -> Der.subjectPublicKeyBits(notASpki));
        }
    }
}
