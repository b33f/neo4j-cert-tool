package com.neo4j.tools.certtool.crypto;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Minimal DER (Distinguished Encoding Rules, X.690) encoder, sufficient to build X.509 v3
 * certificates by hand.
 *
 * <p>The JDK has no public certificate builder API, and this tool deliberately ships without
 * third-party dependencies, so the certificate structure is assembled here. Only the subset of
 * DER that X.509 needs is implemented, and only in the canonical (definite length, minimal
 * encoding) form that DER mandates.
 */
public final class Der {

    public static final int TAG_BOOLEAN = 0x01;
    public static final int TAG_INTEGER = 0x02;
    public static final int TAG_BIT_STRING = 0x03;
    public static final int TAG_OCTET_STRING = 0x04;
    public static final int TAG_NULL = 0x05;
    public static final int TAG_OID = 0x06;
    public static final int TAG_UTF8_STRING = 0x0C;
    public static final int TAG_SEQUENCE = 0x30;
    public static final int TAG_SET = 0x31;
    public static final int TAG_PRINTABLE_STRING = 0x13;
    public static final int TAG_IA5_STRING = 0x16;
    public static final int TAG_UTC_TIME = 0x17;
    public static final int TAG_GENERALIZED_TIME = 0x18;

    /** UTCTime is mandated by RFC 5280 for dates through 2049; GeneralizedTime from 2050. */
    private static final int UTC_TIME_MAX_YEAR = 2049;

    private static final DateTimeFormatter UTC_TIME =
            DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
    private static final DateTimeFormatter GENERALIZED_TIME =
            DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);

    private Der() {}

    /** Encodes a single tag-length-value triple. */
    public static byte[] tlv(int tag, byte[] value) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length + 4);
        out.write(tag);
        writeLength(out, value.length);
        out.writeBytes(value);
        return out.toByteArray();
    }

    private static void writeLength(ByteArrayOutputStream out, int length) {
        if (length < 0x80) {
            out.write(length);
            return;
        }
        int octets = (Integer.SIZE - Integer.numberOfLeadingZeros(length) + 7) / 8;
        out.write(0x80 | octets);
        for (int i = octets - 1; i >= 0; i--) {
            out.write((length >>> (8 * i)) & 0xFF);
        }
    }

    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] part : parts) {
            total += part.length;
        }
        byte[] result = new byte[total];
        int offset = 0;
        for (byte[] part : parts) {
            System.arraycopy(part, 0, result, offset, part.length);
            offset += part.length;
        }
        return result;
    }

    public static byte[] sequence(byte[]... items) {
        return tlv(TAG_SEQUENCE, concat(items));
    }

    public static byte[] set(byte[]... items) {
        return tlv(TAG_SET, concat(items));
    }

    public static byte[] integer(BigInteger value) {
        return tlv(TAG_INTEGER, value.toByteArray());
    }

    public static byte[] integer(long value) {
        return integer(BigInteger.valueOf(value));
    }

    public static byte[] bool(boolean value) {
        return tlv(TAG_BOOLEAN, new byte[] {(byte) (value ? 0xFF : 0x00)});
    }

    public static byte[] nul() {
        return tlv(TAG_NULL, new byte[0]);
    }

    public static byte[] octetString(byte[] value) {
        return tlv(TAG_OCTET_STRING, value);
    }

    /**
     * Encodes a BIT STRING. {@code unusedBits} is the number of ignored low-order bits in the
     * final octet, which DER records in a leading count octet.
     */
    public static byte[] bitString(byte[] bits, int unusedBits) {
        if (unusedBits < 0 || unusedBits > 7) {
            throw new IllegalArgumentException("unusedBits must be 0..7, got " + unusedBits);
        }
        byte[] value = new byte[bits.length + 1];
        value[0] = (byte) unusedBits;
        System.arraycopy(bits, 0, value, 1, bits.length);
        return tlv(TAG_BIT_STRING, value);
    }

    public static byte[] utf8String(String value) {
        return tlv(TAG_UTF8_STRING, value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encodes a PrintableString. The character repertoire is restricted, so callers that cannot
     * guarantee the contents should use {@link #utf8String(String)} instead.
     */
    public static byte[] printableString(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (!isPrintableStringChar(value.charAt(i))) {
                throw new IllegalArgumentException(
                        "Not valid in a DER PrintableString: '" + value.charAt(i) + "'");
            }
        }
        return tlv(TAG_PRINTABLE_STRING, value.getBytes(StandardCharsets.US_ASCII));
    }

    public static boolean isPrintableStringChar(char c) {
        return (c >= 'A' && c <= 'Z')
                || (c >= 'a' && c <= 'z')
                || (c >= '0' && c <= '9')
                || " '()+,-./:=?".indexOf(c) >= 0;
    }

    public static byte[] ia5String(String value) {
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) > 0x7F) {
                throw new IllegalArgumentException("Not valid in a DER IA5String: " + value);
            }
        }
        return tlv(TAG_IA5_STRING, value.getBytes(StandardCharsets.US_ASCII));
    }

    /** Encodes an X.509 Time, choosing UTCTime or GeneralizedTime as RFC 5280 requires. */
    public static byte[] time(Instant instant) {
        ZonedDateTime utc = instant.atZone(ZoneOffset.UTC);
        return utc.getYear() <= UTC_TIME_MAX_YEAR
                ? tlv(TAG_UTC_TIME, UTC_TIME.format(utc).getBytes(StandardCharsets.US_ASCII))
                : tlv(TAG_GENERALIZED_TIME,
                        GENERALIZED_TIME.format(utc).getBytes(StandardCharsets.US_ASCII));
    }

    /** Wraps already-encoded content in a constructed context-specific tag, {@code [n] EXPLICIT}. */
    public static byte[] explicit(int tagNumber, byte[]... encodedContent) {
        return tlv(0xA0 | tagNumber, concat(encodedContent));
    }

    /** Emits raw content under a primitive context-specific tag, as used by GeneralName. */
    public static byte[] contextPrimitive(int tagNumber, byte[] rawContent) {
        return tlv(0x80 | tagNumber, rawContent);
    }

    /** Encodes a dotted-decimal object identifier. */
    public static byte[] oid(String dotted) {
        String[] arcs = dotted.split("\\.");
        if (arcs.length < 2) {
            throw new IllegalArgumentException("An OID needs at least two arcs: " + dotted);
        }
        long first = Long.parseLong(arcs[0]);
        long second = Long.parseLong(arcs[1]);
        if (first < 0 || first > 2) {
            throw new IllegalArgumentException("First OID arc must be 0..2: " + dotted);
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeBase128(out, first * 40 + second);
        for (int i = 2; i < arcs.length; i++) {
            writeBase128(out, Long.parseLong(arcs[i]));
        }
        return tlv(TAG_OID, out.toByteArray());
    }

    private static void writeBase128(ByteArrayOutputStream out, long value) {
        if (value < 0) {
            throw new IllegalArgumentException("Negative OID arc: " + value);
        }
        int significantBits = Math.max(1, Long.SIZE - Long.numberOfLeadingZeros(value));
        int groups = (significantBits + 6) / 7;
        for (int i = groups - 1; i >= 0; i--) {
            int septet = (int) ((value >>> (7 * i)) & 0x7F);
            out.write(i == 0 ? septet : (septet | 0x80));
        }
    }

    /** Decodes the content octets of an OBJECT IDENTIFIER back to dotted-decimal form. */
    public static String decodeOid(byte[] contentOctets) {
        if (contentOctets.length == 0) {
            throw new IllegalArgumentException("Empty OID");
        }
        StringBuilder dotted = new StringBuilder();
        long arc = 0;
        boolean firstArc = true;
        boolean pending = false;
        for (byte octet : contentOctets) {
            arc = (arc << 7) | (octet & 0x7F);
            pending = true;
            if ((octet & 0x80) == 0) {
                if (firstArc) {
                    // The first octet packs two arcs: 40 * arc1 + arc2, with arc1 capped at 2.
                    long arc1 = Math.min(arc / 40, 2);
                    dotted.append(arc1).append('.').append(arc - arc1 * 40);
                    firstArc = false;
                } else {
                    dotted.append('.').append(arc);
                }
                arc = 0;
                pending = false;
            }
        }
        if (pending) {
            throw new IllegalArgumentException("Truncated OID: last arc has no terminating octet");
        }
        return dotted.toString();
    }

    /**
     * Extracts the {@code subjectPublicKey} BIT STRING contents from an X.509
     * SubjectPublicKeyInfo, which is what RFC 5280 hashes to form a key identifier.
     */
    public static byte[] subjectPublicKeyBits(byte[] subjectPublicKeyInfo) {
        Reader spki = new Reader(subjectPublicKeyInfo).readConstructed(TAG_SEQUENCE);
        spki.skipElement(); // AlgorithmIdentifier
        byte[] bitString = spki.readPrimitive(TAG_BIT_STRING);
        if (bitString.length == 0 || bitString[0] != 0) {
            throw new IllegalArgumentException("Unexpected padding in subjectPublicKey BIT STRING");
        }
        byte[] bits = new byte[bitString.length - 1];
        System.arraycopy(bitString, 1, bits, 0, bits.length);
        return bits;
    }

    /**
     * A cursor over DER content, used for the few places where the tool has to read structures
     * the JDK hands it as opaque byte arrays.
     */
    public static final class Reader {
        private final byte[] data;
        private int position;
        private final int end;

        public Reader(byte[] data) {
            this(data, 0, data.length);
        }

        private Reader(byte[] data, int start, int end) {
            this.data = data;
            this.position = start;
            this.end = end;
        }

        public boolean hasNext() {
            return position < end;
        }

        /** Reads the next element, requiring the given tag, and returns a reader over its value. */
        public Reader readConstructed(int expectedTag) {
            int tag = nextTag();
            if (tag != expectedTag) {
                throw new IllegalArgumentException(
                        "Expected DER tag 0x%02X but found 0x%02X".formatted(expectedTag, tag));
            }
            int length = nextLength();
            Reader nested = new Reader(data, position, position + length);
            position += length;
            return nested;
        }

        /** Reads the next element, requiring the given tag, and returns its raw value octets. */
        public byte[] readPrimitive(int expectedTag) {
            int tag = nextTag();
            if (tag != expectedTag) {
                throw new IllegalArgumentException(
                        "Expected DER tag 0x%02X but found 0x%02X".formatted(expectedTag, tag));
            }
            int length = nextLength();
            byte[] value = new byte[length];
            System.arraycopy(data, position, value, 0, length);
            position += length;
            return value;
        }

        /** Returns the tag of the next element without consuming it. */
        public int peekTag() {
            require(1);
            return data[position] & 0xFF;
        }

        public void skipElement() {
            nextTag();
            // nextLength() advances past the length octets, so read it before moving the cursor:
            // 'position += nextLength()' would capture the old position and lose that advance.
            int length = nextLength();
            position += length;
        }

        private int nextTag() {
            require(1);
            int tag = data[position++] & 0xFF;
            if ((tag & 0x1F) == 0x1F) {
                throw new IllegalArgumentException("Multi-octet DER tags are not supported");
            }
            return tag;
        }

        private int nextLength() {
            require(1);
            int first = data[position++] & 0xFF;
            if (first < 0x80) {
                return checkedLength(first);
            }
            int octets = first & 0x7F;
            if (octets == 0 || octets > 4) {
                throw new IllegalArgumentException("Unsupported DER length encoding");
            }
            require(octets);
            long length = 0;
            for (int i = 0; i < octets; i++) {
                length = (length << 8) | (data[position++] & 0xFF);
            }
            if (length > Integer.MAX_VALUE) {
                throw new IllegalArgumentException("DER element too large");
            }
            return checkedLength((int) length);
        }

        private int checkedLength(int length) {
            if (length < 0 || position + length > end) {
                throw new IllegalArgumentException("DER element runs past the end of its parent");
            }
            return length;
        }

        private void require(int octets) {
            if (position + octets > end) {
                throw new IllegalArgumentException("Truncated DER input");
            }
        }
    }
}
