package com.neo4j.tools.certtool.crypto;

import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * Reads and writes PKCS#8 private keys, encrypted under a password with PKCS#5 PBES2.
 *
 * <p>Neo4j requires private keys in PKCS#8 PEM form and supports password protection using PBES2
 * with AES-CBC and an HMAC-SHA PRF. The scheme used here — PBKDF2-HMAC-SHA256 for key derivation
 * and AES-256-CBC for encryption — sits inside that supported set and is what OpenSSL produces
 * for {@code -v2 aes-256-cbc -v2prf hmacWithSHA256}.
 */
public final class Pkcs8 {

    /**
     * SunJCE's name for PBES2 with PBKDF2-HMAC-SHA256 and AES-256-CBC. Present in every JDK since
     * 8, so no provider needs installing.
     */
    public static final String PBES2_ALGORITHM = "PBEWithHmacSHA256AndAES_256";

    /**
     * Default PBKDF2 iteration count. 600,000 is the current OWASP guidance for
     * PBKDF2-HMAC-SHA256, and the cost is paid once when Neo4j loads the key at startup.
     */
    public static final int DEFAULT_ITERATIONS = 600_000;

    /** Salt length in bytes. PBKDF2 salts should be at least 16 bytes. */
    private static final int SALT_BYTES = 16;

    private Pkcs8() {}

    /**
     * Encrypts a private key into a DER-encoded {@code EncryptedPrivateKeyInfo}.
     *
     * <p>The caller keeps ownership of {@code password} and should clear it when finished.
     */
    public static byte[] encrypt(
            PrivateKey privateKey, char[] password, int iterations, SecureRandom random)
            throws GeneralSecurityException, java.io.IOException {
        if (password.length == 0) {
            throw new IllegalArgumentException("Refusing to encrypt a private key with an empty password");
        }
        if (iterations < 10_000) {
            throw new IllegalArgumentException(
                    "PBKDF2 iteration count is too low to be useful: " + iterations);
        }

        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);

        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(PBES2_ALGORITHM);
        SecretKey derivedKey = keyFactory.generateSecret(new PBEKeySpec(password));

        Cipher cipher = Cipher.getInstance(PBES2_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, derivedKey, new PBEParameterSpec(salt, iterations), random);

        byte[] pkcs8 = privateKey.getEncoded();
        try {
            byte[] ciphertext = cipher.doFinal(pkcs8);
            // These parameters carry the salt, iteration count, key length, PRF and the generated
            // AES IV, so the encoded result is self-describing: only the password is needed to
            // read it back.
            AlgorithmParameters parameters = cipher.getParameters();
            return encodeEncryptedPrivateKeyInfo(parameters.getEncoded(), ciphertext);
        } finally {
            // The plaintext PKCS#8 copy is no longer needed; do not leave it on the heap.
            java.util.Arrays.fill(pkcs8, (byte) 0);
        }
    }

    /**
     * Assembles {@code EncryptedPrivateKeyInfo} around the cipher's own parameter encoding.
     *
     * <pre>
     * EncryptedPrivateKeyInfo ::= SEQUENCE {
     *     encryptionAlgorithm AlgorithmIdentifier,
     *     encryptedData       OCTET STRING }
     * </pre>
     *
     * <p>The obvious route — {@code new EncryptedPrivateKeyInfo(AlgorithmParameters, byte[])} —
     * cannot be used here. That constructor maps the parameters back through a generic
     * {@code PBES2} parameters implementation, and doing so drops the PRF from the PBKDF2
     * parameters. The result decodes as PBKDF2's default PRF of HMAC-SHA1 instead of the
     * HMAC-SHA256 that was actually used, so the key derived on reading differs from the key used
     * for encryption and the file cannot be decrypted by anything, including OpenSSL. Wrapping the
     * cipher's untouched parameter encoding avoids the round trip entirely.
     */
    private static byte[] encodeEncryptedPrivateKeyInfo(
            byte[] encodedParameters, byte[] ciphertext) {
        byte[] encryptionAlgorithm = Der.sequence(Der.oid(Oids.PBES2), encodedParameters);
        return Der.sequence(encryptionAlgorithm, Der.octetString(ciphertext));
    }

    /** Decrypts a DER-encoded {@code EncryptedPrivateKeyInfo}. */
    public static PrivateKey decrypt(byte[] encryptedPrivateKeyInfo, char[] password)
            throws GeneralSecurityException, java.io.IOException {
        EncryptedPrivateKeyInfo encrypted = new EncryptedPrivateKeyInfo(encryptedPrivateKeyInfo);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(encrypted.getAlgName());
        SecretKey derivedKey = keyFactory.generateSecret(new PBEKeySpec(password));
        PKCS8EncodedKeySpec keySpec = encrypted.getKeySpec(derivedKey);
        return toPrivateKey(keySpec);
    }

    /** Parses an unencrypted DER-encoded PKCS#8 {@code PrivateKeyInfo}. */
    public static PrivateKey read(byte[] pkcs8) throws GeneralSecurityException {
        return toPrivateKey(new PKCS8EncodedKeySpec(pkcs8));
    }

    private static PrivateKey toPrivateKey(PKCS8EncodedKeySpec keySpec)
            throws GeneralSecurityException {
        byte[] encoded = keySpec.getEncoded();
        try {
            return KeyFactory.getInstance(keyAlgorithm(encoded)).generatePrivate(keySpec);
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    /**
     * Reads the algorithm out of a PKCS#8 {@code PrivateKeyInfo} so the right {@link KeyFactory}
     * can be selected.
     *
     * <pre>
     * PrivateKeyInfo ::= SEQUENCE {
     *     version             INTEGER,
     *     privateKeyAlgorithm AlgorithmIdentifier,
     *     privateKey          OCTET STRING }
     * </pre>
     */
    public static String keyAlgorithm(byte[] pkcs8) {
        Der.Reader privateKeyInfo = new Der.Reader(pkcs8).readConstructed(Der.TAG_SEQUENCE);
        privateKeyInfo.skipElement(); // version
        Der.Reader algorithmIdentifier = privateKeyInfo.readConstructed(Der.TAG_SEQUENCE);
        String oid = Der.decodeOid(algorithmIdentifier.readPrimitive(Der.TAG_OID));
        return switch (oid) {
            case Oids.EC_PUBLIC_KEY -> "EC";
            case Oids.RSA_ENCRYPTION -> "RSA";
            default -> throw new IllegalArgumentException("Unsupported private key algorithm: " + oid);
        };
    }
}
