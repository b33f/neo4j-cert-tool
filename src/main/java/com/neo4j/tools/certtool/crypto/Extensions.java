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
     * <p>{@link InetAddress#ofLiteral} (added in JDK 22) parses literals only and never performs
     * name resolution, so classifying a name cannot trigger a DNS lookup.
     */
    public static InetAddress asIpLiteral(String name) {
        try {
            return InetAddress.ofLiteral(name);
        } catch (IllegalArgumentException notALiteral) {
            return null;
        }
    }

    private static void requireValidDnsName(String name) {
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
