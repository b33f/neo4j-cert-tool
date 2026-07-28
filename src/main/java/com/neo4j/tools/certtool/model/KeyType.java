package com.neo4j.tools.certtool.model;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/** The key algorithms the tool can generate, and how to instantiate each one. */
public enum KeyType {

    /**
     * NIST P-256. The default: ~128-bit security, small keys, fast handshakes, and universally
     * supported by TLS 1.2 and 1.3 stacks including every current Neo4j driver.
     */
    EC_P256("ec-p256", "ec", "EC", "secp256r1", 0),

    /** NIST P-384, for deployments that require a higher security margin. */
    EC_P384("ec-p384", null, "EC", "secp384r1", 0),

    /** RSA 3072-bit, roughly equivalent in strength to P-256. */
    RSA_3072("rsa-3072", null, "RSA", null, 3072),

    /** RSA 4096-bit, for maximum compatibility with older clients and policy requirements. */
    RSA_4096("rsa-4096", "rsa", "RSA", null, 4096);

    private final String canonicalName;
    private final String alias;
    private final String jcaAlgorithm;
    private final String curve;
    private final int keySizeBits;

    KeyType(String canonicalName, String alias, String jcaAlgorithm, String curve, int keySizeBits) {
        this.canonicalName = canonicalName;
        this.alias = alias;
        this.jcaAlgorithm = jcaAlgorithm;
        this.curve = curve;
        this.keySizeBits = keySizeBits;
    }

    public String canonicalName() {
        return canonicalName;
    }

    public String jcaAlgorithm() {
        return jcaAlgorithm;
    }

    /** A short description of the key strength, for the run summary. */
    public String describe() {
        return curve != null ? "EC " + curve : "RSA " + keySizeBits + "-bit";
    }

    public KeyPair generate(SecureRandom random) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(jcaAlgorithm);
        if (curve != null) {
            generator.initialize(new ECGenParameterSpec(curve), random);
        } else {
            generator.initialize(keySizeBits, random);
        }
        return generator.generateKeyPair();
    }

    public static KeyType parse(String value) {
        String normalised = value.trim().toLowerCase(Locale.ROOT);
        for (KeyType type : values()) {
            if (normalised.equals(type.canonicalName) || normalised.equals(type.alias)) {
                return type;
            }
        }
        throw new IllegalArgumentException(
                "Unknown key type '" + value + "'. Choose one of: " + names());
    }

    public static String names() {
        return java.util.Arrays.stream(values())
                .map(KeyType::canonicalName)
                .collect(Collectors.joining(", "));
    }

    /** Aliases accepted in addition to the canonical names, for the help text. */
    public static List<String> aliases() {
        return java.util.Arrays.stream(values())
                .filter(type -> type.alias != null)
                .map(type -> type.alias + " -> " + type.canonicalName)
                .toList();
    }
}
