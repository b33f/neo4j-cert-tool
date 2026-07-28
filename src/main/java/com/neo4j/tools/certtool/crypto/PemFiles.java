package com.neo4j.tools.certtool.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/** Reads the PEM files this tool writes, and the ones a user supplies with {@code --ca-cert}. */
public final class PemFiles {

    private PemFiles() {}

    /**
     * Reads every certificate in a PEM file, in file order.
     *
     * <p>A {@code public.crt} may hold a chain rather than a single certificate, so all blocks are
     * returned.
     */
    public static List<X509Certificate> readCertificates(Path file)
            throws IOException, GeneralSecurityException {
        String document = Files.readString(file, StandardCharsets.UTF_8);
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        List<X509Certificate> certificates = new ArrayList<>();

        String begin = "-----BEGIN " + Pem.LABEL_CERTIFICATE + "-----";
        String end = "-----END " + Pem.LABEL_CERTIFICATE + "-----";
        int from = 0;
        while (true) {
            int start = document.indexOf(begin, from);
            if (start < 0) {
                break;
            }
            int finish = document.indexOf(end, start);
            if (finish < 0) {
                throw new IOException(file + ": unterminated CERTIFICATE block");
            }
            finish += end.length();
            byte[] der = Pem.decode(document.substring(start, finish), Pem.LABEL_CERTIFICATE);
            certificates.add(
                    (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
            from = finish;
        }
        if (certificates.isEmpty()) {
            throw new IOException(file + ": no CERTIFICATE block found");
        }
        return List.copyOf(certificates);
    }

    /**
     * Reads a PKCS#8 private key, encrypted or not.
     *
     * @param password used only when the file holds an encrypted key; may be null otherwise
     */
    public static PrivateKey readPrivateKey(Path file, char[] password)
            throws IOException, GeneralSecurityException {
        String document = Files.readString(file, StandardCharsets.UTF_8);
        if (Pem.contains(document, Pem.LABEL_ENCRYPTED_PRIVATE_KEY)) {
            if (password == null || password.length == 0) {
                throw new IOException(file + " is encrypted but no password was supplied");
            }
            byte[] der = Pem.decode(document, Pem.LABEL_ENCRYPTED_PRIVATE_KEY);
            try {
                return Pkcs8.decrypt(der, password);
            } catch (GeneralSecurityException e) {
                // A wrong password shows up as a padding or integrity failure; say what it means.
                throw new GeneralSecurityException(
                        "Cannot decrypt " + file + " — the password appears to be wrong", e);
            }
        }
        if (Pem.contains(document, Pem.LABEL_PRIVATE_KEY)) {
            return Pkcs8.read(Pem.decode(document, Pem.LABEL_PRIVATE_KEY));
        }
        if (document.contains("-----BEGIN RSA PRIVATE KEY-----")) {
            throw new IOException(
                    file
                            + " is a PKCS#1 key. Neo4j deprecates that format; convert it with:\n"
                            + "  openssl pkcs8 -topk8 -in <file> -out private.key");
        }
        throw new IOException(file + ": no PRIVATE KEY or ENCRYPTED PRIVATE KEY block found");
    }

    /**
     * Checks that a private key belongs to a public key, by signing a nonce and verifying it.
     *
     * <p>This works the same way for RSA and EC without having to compare key parameters by hand.
     */
    public static boolean matches(PrivateKey privateKey, PublicKey publicKey, SecureRandom random) {
        try {
            SignatureAlgorithm algorithm = SignatureAlgorithm.forSigningKey(privateKey);
            byte[] nonce = new byte[32];
            random.nextBytes(nonce);

            Signature signer = Signature.getInstance(algorithm.jcaName());
            signer.initSign(privateKey, random);
            signer.update(nonce);
            byte[] signature = signer.sign();

            Signature verifier = Signature.getInstance(algorithm.jcaName());
            verifier.initVerify(publicKey);
            verifier.update(nonce);
            return verifier.verify(signature);
        } catch (GeneralSecurityException | IllegalArgumentException mismatch) {
            return false;
        }
    }
}
