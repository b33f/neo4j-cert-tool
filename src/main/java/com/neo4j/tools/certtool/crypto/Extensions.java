package com.neo4j.tools.certtool.crypto;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/** Builders for the X.509 v3 extensions this tool emits. */
public final class Extensions {

    /** The nine {@code KeyUsage} bits of RFC 5280 section 4.2.1.3, by bit position. */
    public enum KeyUsage {
        DIGITAL_SIGNATURE(0),
        NON_REPUDIATION(1),
        KEY_ENCIPHERMENT(2),
        DATA_ENCIPHERMENT(3),
        KEY_AGREEMENT(4),
        KEY_CERT_SIGN(5),
        CRL_SIGN(6),
        ENCIPHER_ONLY(7),
        DECIPHER_ONLY(8);

        private final int bit;

        KeyUsage(int bit) {
            this.bit = bit;
        }
    }

    /** A single encoded extension: its OID, criticality flag and DER-encoded value. */
    public record Extension(String oid, boolean critical, byte[] value) {

        public byte[] encoded() {
            // DER omits a field set to its DEFAULT, so critical is only present when true.
            return critical
                    ? Der.sequence(Der.oid(oid), Der.bool(true), Der.octetString(value))
                    : Der.sequence(Der.oid(oid), Der.octetString(value));
        }
    }

    private Extensions() {}

    /** {@code basicConstraints} for a CA. A path length of -1 leaves the constraint unset. */
    public static Extension basicConstraintsCa(int pathLenConstraint) {
        byte[] value = pathLenConstraint < 0
                ? Der.sequence(Der.bool(true))
                : Der.sequence(Der.bool(true), Der.integer(pathLenConstraint));
        return new Extension(Oids.BASIC_CONSTRAINTS, true, value);
    }

    /**
     * {@code basicConstraints} for an end entity. Emitted explicitly and marked critical so that a
     * leaf certificate can never be mistaken for a CA.
     */
    public static Extension basicConstraintsEndEntity() {
        return new Extension(Oids.BASIC_CONSTRAINTS, true, Der.sequence());
    }

    /** {@code keyUsage}, always critical, as RFC 5280 recommends. */
    public static Extension keyUsage(KeyUsage first, KeyUsage... rest) {
        Set<KeyUsage> usages = EnumSet.of(first, rest);
        int highestBit = 0;
        for (KeyUsage usage : usages) {
            highestBit = Math.max(highestBit, usage.bit);
        }
        byte[] bits = new byte[highestBit / 8 + 1];
        for (KeyUsage usage : usages) {
            bits[usage.bit / 8] |= (byte) (0x80 >>> (usage.bit % 8));
        }
        // DER requires the minimal encoding: no trailing zero octets, and the count of the
        // ignored trailing bits in the final octet.
        int unusedBits = 7 - (highestBit % 8);
        return new Extension(Oids.KEY_USAGE, true, Der.bitString(bits, unusedBits));
    }

    /**
     * {@code extendedKeyUsage}. Left non-critical: some TLS stacks reject certificates whose
     * critical EKU omits a purpose they expect, and the usages here are already narrow.
     */
    public static Extension extendedKeyUsage(String... purposeOids) {
        byte[][] purposes = new byte[purposeOids.length][];
        for (int i = 0; i < purposeOids.length; i++) {
            purposes[i] = Der.oid(purposeOids[i]);
        }
        return new Extension(Oids.EXTENDED_KEY_USAGE, false, Der.sequence(purposes));
    }

    /**
     * {@code subjectAltName} holding DNS names and IP addresses. Each name is classified by
     * whether it parses as an IP literal, so an address never lands in a dNSName entry.
     *
     * <p>Neo4j enables {@code verify_hostname} by default from 2025.01, and modern TLS clients
     * ignore the common name entirely, so every address a peer might connect to has to appear
     * here.
     */
    public static Extension subjectAlternativeName(List<String> names) {
        if (names.isEmpty()) {
            throw new IllegalArgumentException("A subjectAltName extension needs at least one name");
        }
        List<byte[]> generalNames = new ArrayList<>(names.size());
        for (String name : names) {
            InetAddress literal = asIpLiteral(name);
            if (literal != null) {
                // iPAddress [7] IMPLICIT OCTET STRING — 4 octets for IPv4, 16 for IPv6.
                generalNames.add(Der.contextPrimitive(7, literal.getAddress()));
            } else {
                requireValidDnsName(name);
                // dNSName [2] IMPLICIT IA5String
                generalNames.add(
                        Der.contextPrimitive(2, name.getBytes(StandardCharsets.US_ASCII)));
            }
        }
        byte[] value = Der.sequence(generalNames.toArray(byte[][]::new));
        // Only critical when there is no subject name to fall back on, per RFC 5280. The
        // certificates here always carry a common name, so non-critical is correct.
        return new Extension(Oids.SUBJECT_ALT_NAME, false, value);
    }

    /**
     * Returns the address if {@code name} is an IP literal, otherwise null.
     *
     * <p>Parsed here rather than through the JDK. {@code InetAddress.ofLiteral} would be the
     * obvious choice but only exists from JDK 22, and this tool supports 21. The alternative,
     * {@link InetAddress#getByName}, is not usable for classification: given a hostname it performs
     * a DNS lookup, so a name that failed to parse as an address would silently become a network
     * request — and a resolvable hostname would be encoded as an {@code iPAddress} entry, which no
     * peer would match. Nothing below resolves anything; a string either parses as a literal or it
     * does not.
     *
     * <p>{@link InetAddress#getByAddress(byte[])} builds the result from raw bytes and never
     * resolves either.
     */
    public static InetAddress asIpLiteral(String name) {
        byte[] address = parseIpLiteral(name);
        if (address == null) {
            return null;
        }
        try {
            return InetAddress.getByAddress(address);
        } catch (java.net.UnknownHostException impossible) {
            // Only thrown for an address of illegal length, and the parser returns 4 or 16 bytes.
            throw new IllegalStateException("Unexpected address length for " + name, impossible);
        }
    }

    /**
     * Parses an IPv4 or IPv6 literal to its raw bytes, or returns null if it is not one.
     *
     * <p>Deliberately stricter than {@code InetAddress.ofLiteral}, which accepts several ambiguous
     * forms that have no place in a certificate:
     *
     * <ul>
     *   <li>{@code 1.2.3} — the legacy three-part form, which the JDK reads as {@code 1.2.0.3}.
     *       Almost always a typo, and inventing an octet from one would be worse than refusing.
     *   <li>{@code 01.2.3.4} — leading zeros. The JDK reads them as decimal, but other stacks read
     *       a leading zero as octal, so {@code 010.1.1.1} can mean two different addresses. An
     *       address that means different things to different readers is not safe to certify.
     *   <li>{@code fe80::1%en0} — a zone identifier. There is no way to encode one in a certificate,
     *       and quietly dropping it would certify an address the caller did not ask for.
     * </ul>
     *
     * <p>Anything rejected here is then validated as a DNS name, so it fails with a message rather
     * than being silently reinterpreted.
     */
    static byte[] parseIpLiteral(String name) {
        if (name == null || name.isEmpty()) {
            return null;
        }
        if (name.indexOf(':') < 0) {
            return parseIpv4(name);
        }
        byte[] address = parseIpv6(name);
        return address == null ? null : unwrapIpv4Mapped(address);
    }

    /**
     * Collapses an IPv4-mapped address ({@code ::ffff:10.0.0.11}) to its four IPv4 octets.
     *
     * <p>RFC 5280 sizes an {@code iPAddress} entry by family, and a peer connecting over IPv4
     * compares a four-octet address. Leaving the 16-octet form in the certificate would produce an
     * entry that never matches. This is also what {@code InetAddress.ofLiteral} does.
     */
    private static byte[] unwrapIpv4Mapped(byte[] address) {
        for (int i = 0; i < 10; i++) {
            if (address[i] != 0) {
                return address;
            }
        }
        if ((address[10] & 0xFF) != 0xFF || (address[11] & 0xFF) != 0xFF) {
            return address;
        }
        return java.util.Arrays.copyOfRange(address, 12, 16);
    }

    /** Strict dotted-quad: exactly four decimal octets, no leading zeros, each 0-255. */
    private static byte[] parseIpv4(String text) {
        byte[] address = new byte[4];
        int octet = 0;
        int start = 0;
        while (octet < 4) {
            int dot = text.indexOf('.', start);
            int end = dot < 0 ? text.length() : dot;
            int value = parseOctet(text, start, end);
            if (value < 0) {
                return null;
            }
            address[octet++] = (byte) value;
            if (dot < 0) {
                // Ran out of text: only valid if that was the fourth octet.
                return octet == 4 ? address : null;
            }
            start = dot + 1;
        }
        // More text after four octets, such as "1.2.3.4.5".
        return null;
    }

    private static int parseOctet(String text, int from, int to) {
        int length = to - from;
        if (length < 1 || length > 3) {
            return -1;
        }
        // A leading zero would be ambiguous — some parsers read it as octal — so reject it.
        if (length > 1 && text.charAt(from) == '0') {
            return -1;
        }
        int value = 0;
        for (int i = from; i < to; i++) {
            int digit = text.charAt(i) - '0';
            if (digit < 0 || digit > 9) {
                return -1;
            }
            value = value * 10 + digit;
        }
        return value <= 255 ? value : -1;
    }

    /**
     * IPv6 as RFC 4291 defines it: eight 16-bit groups, optionally with one {@code ::} standing for
     * one or more all-zero groups, and optionally ending in a dotted-quad.
     *
     * <p>A zone identifier ({@code fe80::1%en0}) is rejected: there is no way to represent one in a
     * certificate, so treating it as an address would be misleading.
     */
    private static byte[] parseIpv6(String text) {
        if (text.indexOf('%') >= 0) {
            return null;
        }
        int compression = text.indexOf("::");
        if (compression >= 0 && text.indexOf("::", compression + 1) >= 0) {
            return null; // "::" may appear at most once
        }

        byte[] address = new byte[16];
        if (compression < 0) {
            return readGroups(text, address, 0, 16, true) == 16 ? address : null;
        }

        String head = text.substring(0, compression);
        String tail = text.substring(compression + 2);

        int headLength = 0;
        if (!head.isEmpty()) {
            // A dotted-quad before the "::" is invalid: it may only occupy the last 32 bits.
            headLength = readGroups(head, address, 0, 16, false);
            if (headLength < 0) {
                return null;
            }
        }
        if (tail.isEmpty()) {
            // Trailing "::" — the remaining groups are zero, which the array already is.
            return headLength < 16 ? address : null;
        }

        byte[] trailing = new byte[16];
        int tailLength = readGroups(tail, trailing, 0, 16 - headLength, true);
        if (tailLength < 0) {
            return null;
        }
        // "::" has to stand for at least one zero group, so the two halves cannot fill the address.
        if (headLength + tailLength >= 16) {
            return null;
        }
        System.arraycopy(trailing, 0, address, 16 - tailLength, tailLength);
        return address;
    }

    /**
     * Reads colon-separated groups into {@code out}, returning the number of bytes written, or -1 if
     * the text is not a valid group sequence. A dotted-quad is accepted only as the final group.
     */
    private static int readGroups(
            String text, byte[] out, int offset, int limit, boolean allowEmbeddedIpv4) {
        int written = 0;
        int start = 0;
        while (true) {
            int colon = text.indexOf(':', start);
            int end = colon < 0 ? text.length() : colon;
            if (end == start) {
                return -1; // an empty group, from a stray or doubled colon
            }
            if (colon < 0 && text.indexOf('.', start) >= 0) {
                if (!allowEmbeddedIpv4) {
                    return -1;
                }
                // A trailing dotted-quad supplies the last two groups.
                byte[] embedded = parseIpv4(text.substring(start));
                if (embedded == null || written + 4 > limit) {
                    return -1;
                }
                System.arraycopy(embedded, 0, out, offset + written, 4);
                return written + 4;
            }
            int group = parseHexGroup(text, start, end);
            if (group < 0 || written + 2 > limit) {
                return -1;
            }
            out[offset + written] = (byte) (group >>> 8);
            out[offset + written + 1] = (byte) group;
            written += 2;
            if (colon < 0) {
                return written;
            }
            start = colon + 1;
        }
    }

    /** One to four hexadecimal digits, as a 16-bit value. */
    private static int parseHexGroup(String text, int from, int to) {
        if (to - from < 1 || to - from > 4) {
            return -1;
        }
        int value = 0;
        for (int i = from; i < to; i++) {
            int digit = Character.digit(text.charAt(i), 16);
            if (digit < 0) {
                return -1;
            }
            value = (value << 4) | digit;
        }
        return value;
    }

    private static void requireValidDnsName(String name) {
        if (name.indexOf(':') >= 0) {
            // A colon can only have been an attempt at an IPv6 address, so say that rather than
            // complaining that it is a bad hostname.
            throw new IllegalArgumentException(
                    "Not a valid IPv6 address: '" + name + "'. Note that a zone identifier such as "
                            + "'%eth0' cannot be represented in a certificate.");
        }
        if (name.isEmpty() || name.length() > 253) {
            throw new IllegalArgumentException("Not a usable DNS name: '" + name + "'");
        }
        for (String label : name.split("\\.", -1)) {
            boolean wildcard = label.equals("*");
            if (label.isEmpty() || label.length() > 63) {
                throw new IllegalArgumentException(
                        "Not a usable DNS name (bad label length): '" + name + "'");
            }
            if (wildcard) {
                continue;
            }
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                boolean allowed = (c >= 'a' && c <= 'z')
                        || (c >= 'A' && c <= 'Z')
                        || (c >= '0' && c <= '9')
                        || c == '-'
                        || c == '_';
                if (!allowed) {
                    throw new IllegalArgumentException(
                            "Not a usable DNS name (illegal character '" + c + "'): '" + name + "'");
                }
            }
        }
    }

    /** {@code subjectKeyIdentifier} derived from the public key. */
    public static Extension subjectKeyIdentifier(PublicKey publicKey) {
        return new Extension(
                Oids.SUBJECT_KEY_IDENTIFIER, false, Der.octetString(keyIdentifier(publicKey)));
    }

    /** {@code authorityKeyIdentifier} pointing at the issuer's key identifier. */
    public static Extension authorityKeyIdentifier(PublicKey issuerPublicKey) {
        byte[] keyIdentifier = Der.contextPrimitive(0, keyIdentifier(issuerPublicKey));
        return new Extension(
                Oids.AUTHORITY_KEY_IDENTIFIER, false, Der.sequence(keyIdentifier));
    }

    /**
     * Computes a key identifier as the SHA-1 digest of the {@code subjectPublicKey} bit string —
     * method (1) of RFC 5280 section 4.2.1.2.
     *
     * <p>SHA-1 is used here purely as a naming function for chain building, not as a security
     * guarantee, and it remains the interoperable choice that every relying party understands.
     * Nothing about the certificate's security depends on its collision resistance.
     */
    public static byte[] keyIdentifier(PublicKey publicKey) {
        try {
            return MessageDigest.getInstance("SHA-1")
                    .digest(Der.subjectPublicKeyBits(publicKey.getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Every JDK ships SHA-1", e);
        }
    }
}
