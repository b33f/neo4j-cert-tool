package com.neo4j.tools.certtool.crypto;

/** Object identifiers used when building X.509 certificates. */
public final class Oids {

    // Attribute types for distinguished names (X.520)
    public static final String COMMON_NAME = "2.5.4.3";
    public static final String COUNTRY = "2.5.4.6";
    public static final String LOCALITY = "2.5.4.7";
    public static final String STATE = "2.5.4.8";
    public static final String ORGANISATION = "2.5.4.10";
    public static final String ORGANISATIONAL_UNIT = "2.5.4.11";

    // Certificate extensions (RFC 5280)
    public static final String SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
    public static final String KEY_USAGE = "2.5.29.15";
    public static final String SUBJECT_ALT_NAME = "2.5.29.17";
    public static final String BASIC_CONSTRAINTS = "2.5.29.19";
    public static final String NAME_CONSTRAINTS = "2.5.29.30";
    public static final String AUTHORITY_KEY_IDENTIFIER = "2.5.29.35";
    public static final String EXTENDED_KEY_USAGE = "2.5.29.37";

    // Extended key usage purposes (RFC 5280 section 4.2.1.12)
    public static final String EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    public static final String EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

    // Password-based encryption (PKCS#5)
    public static final String PBES2 = "1.2.840.113549.1.5.13";

    // Signature and key algorithms
    public static final String RSA_ENCRYPTION = "1.2.840.113549.1.1.1";
    public static final String SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
    public static final String SHA384_WITH_RSA = "1.2.840.113549.1.1.12";
    public static final String SHA512_WITH_RSA = "1.2.840.113549.1.1.13";
    public static final String EC_PUBLIC_KEY = "1.2.840.10045.2.1";
    public static final String ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
    public static final String ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";
    public static final String ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4";

    private Oids() {}
}
