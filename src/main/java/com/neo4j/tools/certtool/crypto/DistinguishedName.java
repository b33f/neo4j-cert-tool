package com.neo4j.tools.certtool.crypto;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An X.501 distinguished name, held as an ordered list of single-valued relative distinguished
 * names.
 *
 * <p>Instances are reused rather than rebuilt when a name appears in two places — a CA's subject
 * name and the issuer name of the certificates it signs, for example — so that both encode to
 * identical bytes. Path validation compares issuer and subject names, and byte-identical
 * encodings keep that comparison unambiguous.
 */
public final class DistinguishedName {

    private final List<Rdn> rdns;

    /** Set instead of {@link #rdns} when the name came from an existing certificate. */
    private final byte[] preEncoded;

    private final String display;

    private DistinguishedName(List<Rdn> rdns) {
        this.rdns = List.copyOf(rdns);
        this.preEncoded = null;
        this.display = null;
    }

    private DistinguishedName(byte[] preEncoded, String display) {
        this.rdns = List.of();
        this.preEncoded = preEncoded.clone();
        this.display = display;
    }

    public static Builder builder() {
        return new Builder();
    }

    /**
     * Adopts an already-encoded name, as found in an existing certificate.
     *
     * <p>Re-encoding a parsed name risks changing the string types or attribute order, which would
     * break the byte comparison path validation performs between an issuer name and its CA's
     * subject name. The original encoding is therefore carried through untouched.
     */
    public static DistinguishedName ofEncoded(byte[] rdnSequence, String display) {
        return new DistinguishedName(rdnSequence, display);
    }

    /**
     * Encodes as {@code RDNSequence}. RFC 5280 orders RDNs from most general to most specific,
     * which matches the order they were added in.
     */
    public byte[] encoded() {
        if (preEncoded != null) {
            return preEncoded.clone();
        }
        byte[][] encodedRdns = new byte[rdns.size()][];
        for (int i = 0; i < rdns.size(); i++) {
            Rdn rdn = rdns.get(i);
            encodedRdns[i] = Der.set(Der.sequence(Der.oid(rdn.oid()), rdn.encodedValue()));
        }
        return Der.sequence(encodedRdns);
    }

    /** Renders in RFC 2253 order (most specific first) for display and log output. */
    @Override
    public String toString() {
        if (display != null) {
            return display;
        }
        List<String> parts = new ArrayList<>(rdns.size());
        for (int i = rdns.size() - 1; i >= 0; i--) {
            Rdn rdn = rdns.get(i);
            parts.add(shortName(rdn.oid()) + "=" + escape(rdn.text()));
        }
        return String.join(",", parts);
    }

    private static String shortName(String oid) {
        return switch (oid) {
            case Oids.COMMON_NAME -> "CN";
            case Oids.COUNTRY -> "C";
            case Oids.LOCALITY -> "L";
            case Oids.STATE -> "ST";
            case Oids.ORGANISATION -> "O";
            case Oids.ORGANISATIONAL_UNIT -> "OU";
            default -> "OID." + oid;
        };
    }

    private static String escape(String value) {
        StringBuilder escaped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (",+\"\\<>;".indexOf(c) >= 0 || (i == 0 && (c == '#' || c == ' '))) {
                escaped.append('\\');
            }
            escaped.append(c);
        }
        return escaped.toString();
    }

    private record Rdn(String oid, String text, byte[] encodedValue) {}

    /** Collects name attributes, skipping any that are absent. */
    public static final class Builder {
        // Keyed by OID so that setting the same attribute twice replaces rather than duplicates.
        private final Map<String, Rdn> attributes = new LinkedHashMap<>();

        private Builder() {}

        /** Adds an attribute encoded as a UTF8String, ignoring null or blank values. */
        public Builder add(String oid, String value) {
            if (value != null && !value.isBlank()) {
                String text = value.strip();
                attributes.put(oid, new Rdn(oid, text, Der.utf8String(text)));
            }
            return this;
        }

        /**
         * Adds a two-letter country code. RFC 5280 requires countryName to be a PrintableString,
         * unlike the other attributes here.
         */
        public Builder country(String value) {
            if (value != null && !value.isBlank()) {
                String text = value.strip().toUpperCase(java.util.Locale.ROOT);
                if (text.length() != 2) {
                    throw new IllegalArgumentException(
                            "Country must be a two-letter ISO 3166 code, got: " + value);
                }
                attributes.put(Oids.COUNTRY, new Rdn(Oids.COUNTRY, text, Der.printableString(text)));
            }
            return this;
        }

        public Builder commonName(String value) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("A certificate subject needs a common name");
            }
            return add(Oids.COMMON_NAME, value);
        }

        public DistinguishedName build() {
            if (attributes.isEmpty()) {
                throw new IllegalStateException("A distinguished name needs at least one attribute");
            }
            // Order the encoding from most general to most specific, as RFC 5280 expects.
            List<Rdn> ordered = new ArrayList<>();
            for (String oid : List.of(
                    Oids.COUNTRY,
                    Oids.STATE,
                    Oids.LOCALITY,
                    Oids.ORGANISATION,
                    Oids.ORGANISATIONAL_UNIT,
                    Oids.COMMON_NAME)) {
                Rdn rdn = attributes.get(oid);
                if (rdn != null) {
                    ordered.add(rdn);
                }
            }
            // Anything outside the known set keeps insertion order at the end.
            for (Map.Entry<String, Rdn> entry : attributes.entrySet()) {
                if (!ordered.contains(entry.getValue())) {
                    ordered.add(entry.getValue());
                }
            }
            return new DistinguishedName(ordered);
        }
    }
}
