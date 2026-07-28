package com.neo4j.tools.certtool.crypto;

import java.security.PrivateKey;

/** The signature algorithms this tool will sign certificates with. */
public enum SignatureAlgorithm {
    SHA256_WITH_RSA("SHA256withRSA", Oids.SHA256_WITH_RSA, true),
    SHA384_WITH_RSA("SHA384withRSA", Oids.SHA384_WITH_RSA, true),
    SHA512_WITH_RSA("SHA512withRSA", Oids.SHA512_WITH_RSA, true),
    SHA256_WITH_ECDSA("SHA256withECDSA", Oids.ECDSA_WITH_SHA256, false),
    SHA384_WITH_ECDSA("SHA384withECDSA", Oids.ECDSA_WITH_SHA384, false),
    SHA512_WITH_ECDSA("SHA512withECDSA", Oids.ECDSA_WITH_SHA512, false);

    private final String jcaName;
    private final String oid;
    private final boolean absentParametersEncodedAsNull;

    SignatureAlgorithm(String jcaName, String oid, boolean absentParametersEncodedAsNull) {
        this.jcaName = jcaName;
        this.oid = oid;
        this.absentParametersEncodedAsNull = absentParametersEncodedAsNull;
    }

    public String jcaName() {
        return jcaName;
    }

    /**
     * Encodes as {@code AlgorithmIdentifier}. RFC 4055 requires an explicit NULL parameters field
     * for the RSA PKCS#1 v1.5 algorithms, while RFC 5758 requires it to be absent for ECDSA.
     */
    public byte[] algorithmIdentifier() {
        return absentParametersEncodedAsNull
                ? Der.sequence(Der.oid(oid), Der.nul())
                : Der.sequence(Der.oid(oid));
    }

    /** Picks a signature algorithm whose digest strength matches the signing key. */
    public static SignatureAlgorithm forSigningKey(PrivateKey key) {
        return switch (key.getAlgorithm()) {
            case "RSA", "RSASSA-PSS" -> SHA256_WITH_RSA;
            case "EC", "ECDSA" -> matchEcCurveStrength(key);
            default -> throw new IllegalArgumentException(
                    "Cannot sign certificates with a " + key.getAlgorithm() + " key");
        };
    }

    private static SignatureAlgorithm matchEcCurveStrength(PrivateKey key) {
        // Pair the digest with the curve size so the hash is not the weakest link in the signature.
        int fieldBits = key instanceof java.security.interfaces.ECKey ecKey
                ? ecKey.getParams().getCurve().getField().getFieldSize()
                : 256;
        if (fieldBits > 384) {
            return SHA512_WITH_ECDSA;
        }
        return fieldBits > 256 ? SHA384_WITH_ECDSA : SHA256_WITH_ECDSA;
    }
}
