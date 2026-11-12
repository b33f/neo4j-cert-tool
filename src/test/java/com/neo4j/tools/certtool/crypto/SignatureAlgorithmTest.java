package com.neo4j.tools.certtool.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.neo4j.tools.certtool.model.KeyType;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Checks that the signature digest is never the weakest link in a certificate: the digest strength
 * must rise with the signing key's strength, and weak or unknown keys must be refused outright.
 */
class SignatureAlgorithmTest {

    private final SecureRandom random = new SecureRandom();

    @Test
    @DisplayName("P-256 keys are signed with SHA-256")
    void p256GetsSha256() throws Exception {
        assertEquals(
                "SHA256withECDSA",
                SignatureAlgorithm.forSigningKey(KeyType.EC_P256.generate(random).getPrivate()).jcaName());
    }

    @Test
    @DisplayName("P-384 keys are signed with SHA-384")
    void p384GetsSha384() throws Exception {
        assertEquals(
                "SHA384withECDSA",
                SignatureAlgorithm.forSigningKey(KeyType.EC_P384.generate(random).getPrivate()).jcaName());
    }

    @Test
    @DisplayName("P-521 keys are signed with SHA-512")
    void p521GetsSha512() throws Exception {
        // P-521 is not a KeyType the tool generates, but the mapping should still scale with it.
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp521r1"), random);

        assertEquals(
                "SHA512withECDSA",
                SignatureAlgorithm.forSigningKey(generator.generateKeyPair().getPrivate()).jcaName());
    }

    @Test
    @DisplayName("RSA keys are signed with SHA-256")
    void rsaGetsSha256() throws Exception {
        assertEquals(
                "SHA256withRSA",
                SignatureAlgorithm.forSigningKey(KeyType.RSA_3072.generate(random).getPrivate()).jcaName());
    }

    @Test
    @DisplayName("a key of unsupported type is refused, not signed with some default")
    void unsupportedKeysAreRefused() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("DSA");
        generator.initialize(1024, random);

        assertThrows(
                IllegalArgumentException.class,
                () -> SignatureAlgorithm.forSigningKey(generator.generateKeyPair().getPrivate()));
    }
}
