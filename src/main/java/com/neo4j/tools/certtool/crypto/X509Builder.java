package com.neo4j.tools.certtool.crypto;

import com.neo4j.tools.certtool.crypto.Extensions.Extension;
import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds and signs X.509 v3 certificates using only JDK cryptography.
 *
 * <p>The finished certificate is handed back through the JDK's own {@link CertificateFactory},
 * which parses and validates the structure. A malformed encoding therefore fails here rather than
 * at the far end of a TLS handshake.
 */
public final class X509Builder {

    /** Serial number entropy in bits. The CA/Browser Forum requires at least 64. */
    private static final int SERIAL_BITS = 128;

    /**
     * How far back to date {@code notBefore}, to absorb clock skew between the machine generating
     * the certificate and the cluster members using it.
     */
    private static final Duration BACKDATE = Duration.ofMinutes(5);

    private final SecureRandom random;
    private BigInteger serialNumber;
    private DistinguishedName issuer;
    private DistinguishedName subject;
    private PublicKey publicKey;
    private Instant notBefore;
    private Instant notAfter;
    private final List<Extension> extensions = new ArrayList<>();

    public X509Builder(SecureRandom random) {
        this.random = random;
    }

    public X509Builder subject(DistinguishedName subject) {
        this.subject = subject;
        return this;
    }

    public X509Builder issuer(DistinguishedName issuer) {
        this.issuer = issuer;
        return this;
    }

    public X509Builder publicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
        return this;
    }

    /** Sets validity from {@code from}, backdated slightly to tolerate clock skew. */
    public X509Builder validity(Instant from, long days) {
        if (days < 1) {
            throw new IllegalArgumentException("Validity must be at least one day, got " + days);
        }
        this.notBefore = from.minus(BACKDATE).truncatedTo(ChronoUnit.SECONDS);
        this.notAfter = from.plus(days, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
        return this;
    }

    public X509Builder addExtension(Extension extension) {
        extensions.add(extension);
        return this;
    }

    /** Overrides the randomly generated serial number. Intended for tests. */
    public X509Builder serialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
        return this;
    }

    /**
     * Signs the certificate with the issuer's private key.
     *
     * @param issuerPrivateKey the CA key, or the certificate's own key when self-signing
     */
    public X509Certificate signWith(PrivateKey issuerPrivateKey, SignatureAlgorithm algorithm)
            throws GeneralSecurityException {
        requireComplete();

        byte[] tbsCertificate = encodeTbsCertificate(algorithm);

        Signature signature = Signature.getInstance(algorithm.jcaName());
        signature.initSign(issuerPrivateKey, random);
        signature.update(tbsCertificate);
        byte[] signatureValue = signature.sign();

        byte[] certificate = Der.sequence(
                tbsCertificate, algorithm.algorithmIdentifier(), Der.bitString(signatureValue, 0));

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate)
                factory.generateCertificate(new ByteArrayInputStream(certificate));
    }

    private byte[] encodeTbsCertificate(SignatureAlgorithm algorithm) {
        BigInteger serial = serialNumber != null ? serialNumber : randomSerialNumber();

        byte[][] encodedExtensions = new byte[extensions.size()][];
        for (int i = 0; i < extensions.size(); i++) {
            encodedExtensions[i] = extensions.get(i).encoded();
        }

        // TBSCertificate, RFC 5280 section 4.1. The version field is [0] EXPLICIT and holds 2
        // for v3; extensions are [3] EXPLICIT and are omitted entirely when there are none.
        byte[] base = Der.concat(
                Der.explicit(0, Der.integer(2)),
                Der.integer(serial),
                algorithm.algorithmIdentifier(),
                issuer.encoded(),
                Der.sequence(Der.time(notBefore), Der.time(notAfter)),
                subject.encoded(),
                // getEncoded() on a public key is already a DER SubjectPublicKeyInfo.
                publicKey.getEncoded());

        return extensions.isEmpty()
                ? Der.tlv(Der.TAG_SEQUENCE, base)
                : Der.tlv(
                        Der.TAG_SEQUENCE,
                        Der.concat(base, Der.explicit(3, Der.sequence(encodedExtensions))));
    }

    private BigInteger randomSerialNumber() {
        // A positive, non-zero serial number, as RFC 5280 section 4.1.2.2 requires.
        BigInteger serial;
        do {
            serial = new BigInteger(SERIAL_BITS, random);
        } while (serial.signum() == 0);
        return serial;
    }

    private void requireComplete() {
        if (subject == null) {
            throw new IllegalStateException("subject is required");
        }
        if (issuer == null) {
            throw new IllegalStateException("issuer is required");
        }
        if (publicKey == null) {
            throw new IllegalStateException("publicKey is required");
        }
        if (notBefore == null || notAfter == null) {
            throw new IllegalStateException("validity is required");
        }
    }
}
