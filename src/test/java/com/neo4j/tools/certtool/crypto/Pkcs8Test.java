package com.neo4j.tools.certtool.crypto;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.model.KeyType;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import javax.crypto.EncryptedPrivateKeyInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Checks that private keys are encrypted in a form Neo4j and OpenSSL both accept. */
class Pkcs8Test {

    private static final char[] PASSWORD = "correct horse battery staple".toCharArray();

    /** Kept low so the tests stay fast; the production default is much higher. */
    private static final int TEST_ITERATIONS = 10_000;

    private final SecureRandom random = new SecureRandom();

    @ParameterizedTest
    @EnumSource(KeyType.class)
    void encryptedKeysRoundTripForEveryKeyType(KeyType keyType) throws Exception {
        KeyPair keyPair = keyType.generate(random);
        byte[] encrypted = Pkcs8.encrypt(keyPair.getPrivate(), PASSWORD, TEST_ITERATIONS, random);

        PrivateKey decrypted = Pkcs8.decrypt(encrypted, PASSWORD);

        assertEquals(keyPair.getPrivate().getAlgorithm(), decrypted.getAlgorithm());
        assertArrayEquals(keyPair.getPrivate().getEncoded(), decrypted.getEncoded());
    }

    @Test
    void theWrongPasswordFails() throws Exception {
        KeyPair keyPair = KeyType.EC_P256.generate(random);
        byte[] encrypted = Pkcs8.encrypt(keyPair.getPrivate(), PASSWORD, TEST_ITERATIONS, random);

        assertThrows(
                GeneralSecurityException.class,
                () -> Pkcs8.decrypt(encrypted, "not the password".toCharArray()));
    }

    @Test
    void aTruncatedPasswordFails() throws Exception {
        // Guards against a bug where only part of the password reached the key derivation.
        KeyPair keyPair = KeyType.EC_P256.generate(random);
        byte[] encrypted = Pkcs8.encrypt(keyPair.getPrivate(), PASSWORD, TEST_ITERATIONS, random);

        assertThrows(
                GeneralSecurityException.class,
                () -> Pkcs8.decrypt(encrypted, "correct horse battery stapl".toCharArray()));
    }

    @Test
    void theSameKeyEncryptsDifferentlyEachTime() throws Exception {
        // A fresh salt and IV per invocation, so two files never reveal that they hold the
        // same key or were protected with the same password.
        KeyPair keyPair = KeyType.EC_P256.generate(random);
        byte[] first = Pkcs8.encrypt(keyPair.getPrivate(), PASSWORD, TEST_ITERATIONS, random);
        byte[] second = Pkcs8.encrypt(keyPair.getPrivate(), PASSWORD, TEST_ITERATIONS, random);

        assertNotEquals(
                java.util.HexFormat.of().formatHex(first), java.util.HexFormat.of().formatHex(second));
    }

    @Test
    void emptyPasswordsAreRefused() throws Exception {
        KeyPair keyPair = KeyType.EC_P256.generate(random);
        assertThrows(
                IllegalArgumentException.class,
                () -> Pkcs8.encrypt(keyPair.getPrivate(), new char[0], TEST_ITERATIONS, random));
    }

    @Test
    void tooFewIterationsAreRefused() throws Exception {
        KeyPair keyPair = KeyType.EC_P256.generate(random);
        assertThrows(
                IllegalArgumentException.class,
                () -> Pkcs8.encrypt(keyPair.getPrivate(), PASSWORD, 1000, random));
    }

    @Test
    void theEncryptionSchemeIsPbes2WithAes256AndHmacSha256() throws Exception {
        KeyPair keyPair = KeyType.EC_P256.generate(random);
        byte[] encrypted = Pkcs8.encrypt(keyPair.getPrivate(), PASSWORD, TEST_ITERATIONS, random);

        // The JDK resolves the OIDs and parameters in the structure back to a scheme name. If the
        // PRF were lost in encoding this would come back as PBEWithHmacSHA1AndAES_256, which is
        // both weaker than intended and undecryptable with the key that was actually used.
        EncryptedPrivateKeyInfo parsed = new EncryptedPrivateKeyInfo(encrypted);
        assertEquals("PBEWithHmacSHA256AndAES_256", parsed.getAlgName());
    }

    @Test
    void theIterationCountReachesTheEncodedParameters() throws Exception {
        KeyPair keyPair = KeyType.EC_P256.generate(random);
        int iterations = 12_345;
        byte[] encrypted = Pkcs8.encrypt(keyPair.getPrivate(), PASSWORD, iterations, random);

        assertEquals(iterations, pbkdf2IterationCount(encrypted));
    }

    @Test
    void theSaltIsSixteenBytes() throws Exception {
        KeyPair keyPair = KeyType.EC_P256.generate(random);
        byte[] encrypted = Pkcs8.encrypt(keyPair.getPrivate(), PASSWORD, TEST_ITERATIONS, random);

        assertEquals(16, pbkdf2Salt(encrypted).length);
    }

    @ParameterizedTest
    @EnumSource(KeyType.class)
    void theKeyAlgorithmCanBeReadBackFromAnUnencryptedKey(KeyType keyType) throws Exception {
        KeyPair keyPair = keyType.generate(random);
        assertEquals(
                keyType.jcaAlgorithm(), Pkcs8.keyAlgorithm(keyPair.getPrivate().getEncoded()));
    }

    @Test
    void anUnknownKeyAlgorithmIsReported() {
        // A PrivateKeyInfo whose algorithm OID is not one the tool supports.
        byte[] pkcs8 = Der.sequence(
                Der.integer(0),
                Der.sequence(Der.oid("1.2.3.4"), Der.nul()),
                Der.octetString(new byte[] {0x01}));
        assertThrows(IllegalArgumentException.class, () -> Pkcs8.keyAlgorithm(pkcs8));
    }

    @Test
    void unencryptedKeysCanStillBeRead() throws Exception {
        KeyPair keyPair = KeyType.EC_P256.generate(random);
        PrivateKey read = Pkcs8.read(keyPair.getPrivate().getEncoded());
        assertArrayEquals(keyPair.getPrivate().getEncoded(), read.getEncoded());
    }

    // --- Helpers that walk the PBES2 structure ---------------------------------------------

    /**
     * Extracts the PBKDF2 iteration count.
     *
     * <pre>
     * EncryptedPrivateKeyInfo ::= SEQUENCE {
     *   encryptionAlgorithm SEQUENCE {
     *     OID pbes2,
     *     PBES2-params SEQUENCE {
     *       keyDerivationFunc SEQUENCE { OID pbkdf2, PBKDF2-params SEQUENCE {
     *           salt OCTET STRING, iterationCount INTEGER, ... } },
     *       encryptionScheme  SEQUENCE { OID aes256-CBC, IV OCTET STRING } } },
     *   encryptedData OCTET STRING }
     * </pre>
     */
    private static int pbkdf2IterationCount(byte[] encrypted) {
        Der.Reader parameters = pbkdf2Parameters(encrypted);
        parameters.skipElement(); // salt
        return new BigInteger(parameters.readPrimitive(Der.TAG_INTEGER)).intValueExact();
    }

    private static byte[] pbkdf2Salt(byte[] encrypted) {
        return pbkdf2Parameters(encrypted).readPrimitive(Der.TAG_OCTET_STRING);
    }

    private static Der.Reader pbkdf2Parameters(byte[] encrypted) {
        Der.Reader top = new Der.Reader(encrypted).readConstructed(Der.TAG_SEQUENCE);
        Der.Reader encryptionAlgorithm = top.readConstructed(Der.TAG_SEQUENCE);
        assertEquals(Oids.PBES2, Der.decodeOid(encryptionAlgorithm.readPrimitive(Der.TAG_OID)));
        Der.Reader pbes2Params = encryptionAlgorithm.readConstructed(Der.TAG_SEQUENCE);
        Der.Reader keyDerivationFunc = pbes2Params.readConstructed(Der.TAG_SEQUENCE);
        // 1.2.840.113549.1.5.12 is PBKDF2.
        assertEquals("1.2.840.113549.1.5.12", Der.decodeOid(keyDerivationFunc.readPrimitive(Der.TAG_OID)));
        return keyDerivationFunc.readConstructed(Der.TAG_SEQUENCE);
    }

    @Test
    void theEncryptionSchemeIsAes256Cbc() throws Exception {
        KeyPair keyPair = KeyType.EC_P256.generate(random);
        byte[] encrypted = Pkcs8.encrypt(keyPair.getPrivate(), PASSWORD, TEST_ITERATIONS, random);

        Der.Reader top = new Der.Reader(encrypted).readConstructed(Der.TAG_SEQUENCE);
        Der.Reader encryptionAlgorithm = top.readConstructed(Der.TAG_SEQUENCE);
        encryptionAlgorithm.skipElement(); // pbes2 OID
        Der.Reader pbes2Params = encryptionAlgorithm.readConstructed(Der.TAG_SEQUENCE);
        pbes2Params.skipElement(); // keyDerivationFunc
        Der.Reader encryptionScheme = pbes2Params.readConstructed(Der.TAG_SEQUENCE);

        // 2.16.840.1.101.3.4.1.42 is aes256-CBC-PAD, which is in the set Neo4j documents as
        // supported for encrypted private keys.
        assertEquals(
                "2.16.840.1.101.3.4.1.42",
                Der.decodeOid(encryptionScheme.readPrimitive(Der.TAG_OID)));
        assertEquals(16, encryptionScheme.readPrimitive(Der.TAG_OCTET_STRING).length, "AES block-sized IV");
    }

    @Test
    void thePbkdf2PrfIsHmacSha256() throws Exception {
        KeyPair keyPair = KeyType.EC_P256.generate(random);
        byte[] encrypted = Pkcs8.encrypt(keyPair.getPrivate(), PASSWORD, TEST_ITERATIONS, random);

        Der.Reader parameters = pbkdf2Parameters(encrypted);
        parameters.skipElement(); // salt
        parameters.skipElement(); // iterationCount
        if (parameters.hasNext() && parameters.peekTag() == Der.TAG_INTEGER) {
            parameters.skipElement(); // keyLength, which is optional and precedes the PRF
        }
        assertTrue(
                parameters.hasNext(),
                "the PBKDF2 parameters must state the PRF explicitly, because the default is "
                        + "HMAC-SHA1 and a reader would then derive the wrong key");
        Der.Reader prf = parameters.readConstructed(Der.TAG_SEQUENCE);
        // 1.2.840.113549.2.9 is hmacWithSHA256.
        assertEquals("1.2.840.113549.2.9", Der.decodeOid(prf.readPrimitive(Der.TAG_OID)));
    }
}
