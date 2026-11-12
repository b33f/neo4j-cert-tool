package com.neo4j.tools.certtool.model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.crypto.SignatureAlgorithm;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Checks that the keys the tool generates actually have the strength each {@link KeyType} claims.
 *
 * <p>Everything downstream — the PKCS#8 wrapping, the certificate fields, the handshake — can be
 * correct while the keys themselves are silently weaker than advertised, so the raw key material is
 * asserted here directly.
 */
class KeyTypeTest {

    private final SecureRandom random = new SecureRandom();

    @ParameterizedTest
    @EnumSource(KeyType.class)
    @DisplayName("generated keys have the claimed algorithm and strength")
    void generatedKeysHaveTheClaimedStrength(KeyType keyType) throws Exception {
        KeyPair keyPair = keyType.generate(random);

        switch (keyPair.getPublic()) {
            case ECPublicKey ecKey -> {
                ECParameterSpec expected = curveParameters(expectedCurve(keyType));
                assertEquals(
                        expected.getCurve(),
                        ecKey.getParams().getCurve(),
                        keyType + " must generate on " + expectedCurve(keyType)
                                + ", not just any curve of the same size");
            }
            case RSAPublicKey rsaKey -> assertEquals(
                    expectedRsaBits(keyType),
                    rsaKey.getModulus().bitLength(),
                    keyType + " must generate the advertised modulus size");
            default -> throw new AssertionError(
                    "unexpected key type: " + keyPair.getPublic().getClass());
        }
    }

    @ParameterizedTest
    @EnumSource(KeyType.class)
    @DisplayName("the private key can sign and its public key verifies")
    void thePrivateKeyBelongsToItsPublicKey(KeyType keyType) throws Exception {
        KeyPair keyPair = keyType.generate(random);
        byte[] message = "a payload to sign".getBytes(StandardCharsets.UTF_8);

        String algorithm = SignatureAlgorithm.forSigningKey(keyPair.getPrivate()).jcaName();
        Signature signer = Signature.getInstance(algorithm);
        signer.initSign(keyPair.getPrivate());
        signer.update(message);
        byte[] signature = signer.sign();

        Signature verifier = Signature.getInstance(algorithm);
        verifier.initVerify(keyPair.getPublic());
        verifier.update(message);

        assertTrue(verifier.verify(signature), keyType + " private and public keys must match");
    }

    @Test
    @DisplayName("two generated key pairs are never the same")
    void generatedKeyPairsAreDistinct() throws Exception {
        KeyPair first = KeyType.EC_P256.generate(random);
        KeyPair second = KeyType.EC_P256.generate(random);

        assertNotEquals(
                hex(first.getPrivate().getEncoded()),
                hex(second.getPrivate().getEncoded()),
                "a fixed or repeated key would hand every deployment the same private key");
    }

    @Test
    @DisplayName("key generation draws randomness from the source it was given")
    void generationConsumesTheSuppliedRandomness() throws Exception {
        RecordingRandom random = new RecordingRandom();
        KeyType.EC_P256.generate(random);

        assertTrue(
                random.bytesRequested >= 32,
                "key generation must draw at least a seed's worth of entropy from the "
                        + "supplied SecureRandom; drawing none would mean a hardcoded source");
    }

    @Test
    @DisplayName("every key type rejects an unknown name")
    void unknownNamesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> KeyType.parse("rsa-1024"));
        assertThrows(IllegalArgumentException.class, () -> KeyType.parse(""));
    }

    @Test
    @DisplayName("aliases resolve to the same key type as the canonical name")
    void aliasesResolve() {
        assertEquals(KeyType.EC_P256, KeyType.parse("ec"));
        assertEquals(KeyType.RSA_4096, KeyType.parse("rsa"));
        assertEquals(KeyType.RSA_3072, KeyType.parse("RSA-3072"));
    }

    // --- Helpers -----------------------------------------------------------------------------

    private static String expectedCurve(KeyType keyType) {
        return switch (keyType) {
            case EC_P256 -> "secp256r1";
            case EC_P384 -> "secp384r1";
            default -> throw new AssertionError(keyType + " is not an EC key type");
        };
    }

    private static int expectedRsaBits(KeyType keyType) {
        return switch (keyType) {
            case RSA_3072 -> 3072;
            case RSA_4096 -> 4096;
            default -> throw new AssertionError(keyType + " is not an RSA key type");
        };
    }

    /** The standard parameters for a named curve, read from the JCA rather than hand-built. */
    private static ECParameterSpec curveParameters(String name) throws Exception {
        var parameters = java.security.AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec(name));
        return parameters.getParameterSpec(ECParameterSpec.class);
    }

    private static String hex(byte[] bytes) {
        return java.util.HexFormat.of().formatHex(bytes);
    }

    /** Counts how much randomness is actually drawn, delegating to a real source. */
    private static final class RecordingRandom extends SecureRandom {
        private static final long serialVersionUID = 1L;

        int bytesRequested;

        @Override
        public void nextBytes(byte[] bytes) {
            bytesRequested += bytes.length;
            super.nextBytes(bytes);
        }
    }
}
