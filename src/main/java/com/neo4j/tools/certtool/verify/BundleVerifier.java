package com.neo4j.tools.certtool.verify;

import com.neo4j.tools.certtool.PasswordProvider;
import com.neo4j.tools.certtool.crypto.Oids;
import com.neo4j.tools.certtool.crypto.PemFiles;
import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.output.FilePermissions;
import com.neo4j.tools.certtool.output.Layout;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Stream;

/**
 * Re-reads generated material from disk and checks that it is what Neo4j needs.
 *
 * <p>Everything is checked against the files as they exist, not against the in-memory objects that
 * produced them, so this catches encoding, permission and distribution mistakes as well as
 * generation bugs. The same checks run in the test suite and behind the {@code verify} command.
 */
public final class BundleVerifier {

    /** How serious a finding is. */
    public enum Severity {
        /** The material will not work, or is not safe to use. */
        ERROR,
        /** Worth attention but not fatal. */
        WARNING,
        /** A check that passed. */
        OK
    }

    /** One check outcome. */
    public record Finding(Severity severity, String location, String message) {

        @Override
        public String toString() {
            String marker = switch (severity) {
                case ERROR -> "FAIL";
                case WARNING -> "WARN";
                case OK -> " ok ";
            };
            return "[%s] %-28s %s".formatted(marker, location, message);
        }
    }

    /** Everything found during one verification run. */
    public record Report(List<Finding> findings) {

        public boolean hasErrors() {
            return findings.stream().anyMatch(f -> f.severity() == Severity.ERROR);
        }

        public List<Finding> problems() {
            return findings.stream().filter(f -> f.severity() != Severity.OK).toList();
        }

        public long checksRun() {
            return findings.size();
        }
    }

    /** Minimum acceptable RSA modulus size. */
    private static final int MINIMUM_RSA_BITS = 2048;

    /** Minimum acceptable EC field size. */
    private static final int MINIMUM_EC_BITS = 256;

    /** Warn when a leaf certificate has less than this long to run. */
    private static final long EXPIRY_WARNING_DAYS = 30;

    private final PasswordProvider passwords;
    private final SecureRandom random;
    private final Instant now;
    private final List<Finding> findings = new ArrayList<>();

    public BundleVerifier(PasswordProvider passwords, SecureRandom random, Instant now) {
        this.passwords = passwords;
        this.random = random;
        this.now = now;
    }

    /**
     * Verifies a staging directory containing per-node bundles, or a single bundle — either a
     * {@code out/<node>} directory or a {@code NEO4J_HOME}.
     */
    public Report verify(Path root) throws IOException {
        if (!Files.isDirectory(root)) {
            error(root.toString(), "not a directory");
            return new Report(List.copyOf(findings));
        }

        List<Path> bundles = new ArrayList<>();
        if (Files.isDirectory(Layout.certificates(root))) {
            bundles.add(root);
        } else {
            try (Stream<Path> children = Files.list(root)) {
                children.filter(Files::isDirectory)
                        .filter(child -> Files.isDirectory(Layout.certificates(child)))
                        .sorted()
                        .forEach(bundles::add);
            }
        }

        if (bundles.isEmpty()) {
            error(
                    root.toString(),
                    "no certificates/ directory here or in any subdirectory — is this the right path?");
            return new Report(List.copyOf(findings));
        }

        for (Path bundle : bundles) {
            verifyBundle(bundle);
        }
        return new Report(List.copyOf(findings));
    }

    private void verifyBundle(Path bundle) throws IOException {
        String nodeName = bundle.getFileName() == null ? bundle.toString() : bundle.getFileName().toString();
        boolean anyScope = false;
        for (Scope scope : Scope.values()) {
            Path scopeDirectory = Layout.scope(bundle, scope);
            if (!Files.isDirectory(scopeDirectory)) {
                continue;
            }
            anyScope = true;
            verifyScope(nodeName, bundle, scope);
        }
        if (!anyScope) {
            error(nodeName, "certificates/ contains none of the known scopes: " + Scope.names());
        }
    }

    private void verifyScope(String nodeName, Path bundle, Scope scope) {
        String location = nodeName + "/" + scope.directoryName();
        Path certificateFile = Layout.publicCertificate(bundle, scope);
        Path keyFile = Layout.privateKey(bundle, scope);
        Path trustedDirectory = Layout.trusted(bundle, scope);

        try {
            if (!Files.isRegularFile(certificateFile)) {
                error(location, "missing " + Layout.PUBLIC_CERTIFICATE_FILE);
                return;
            }
            if (!Files.isRegularFile(keyFile)) {
                error(location, "missing " + Layout.PRIVATE_KEY_FILE);
                return;
            }
            if (!Files.isDirectory(Layout.revoked(bundle, scope))) {
                error(location, "missing " + Layout.REVOKED_DIRECTORY + "/ directory");
            } else {
                ok(location, Layout.REVOKED_DIRECTORY + "/ present");
            }

            List<X509Certificate> chain = PemFiles.readCertificates(certificateFile);
            X509Certificate leaf = chain.getFirst();
            ok(location, "certificate parses: " + leaf.getSubjectX500Principal().getName());

            checkPermissions(location, keyFile, certificateFile, trustedDirectory);
            checkValidity(location, leaf);
            checkKeyStrength(location, leaf.getPublicKey());
            checkSignatureAlgorithm(location, chain);
            checkExtensions(location, scope, leaf);
            checkSubjectAlternativeNames(location, leaf);
            checkPrivateKey(location, keyFile, nodeName, leaf.getPublicKey());
            checkChain(location, chain, trustedDirectory);
        } catch (IOException | GeneralSecurityException e) {
            error(location, e.getMessage());
        }
    }

    // --- Individual checks -----------------------------------------------------------------

    private void checkPermissions(
            String location, Path keyFile, Path certificateFile, Path trustedDirectory) {
        if (!FilePermissions.posixSupported()) {
            warning(location, "file system has no POSIX permissions, so they were not checked");
            return;
        }
        try {
            Set<java.nio.file.attribute.PosixFilePermission> keyPermissions =
                    FilePermissions.read(keyFile);
            if (FilePermissions.readableByOthers(keyFile)) {
                error(
                        location,
                        "%s is %s — it must not be readable beyond its owner"
                                .formatted(
                                        Layout.PRIVATE_KEY_FILE,
                                        FilePermissions.describe(keyPermissions)));
            } else {
                ok(
                        location,
                        "%s permissions %s"
                                .formatted(
                                        Layout.PRIVATE_KEY_FILE,
                                        FilePermissions.describe(keyPermissions)));
            }
            if (!Files.isReadable(certificateFile)) {
                error(location, Layout.PUBLIC_CERTIFICATE_FILE + " is not readable");
            }
            if (Files.isDirectory(trustedDirectory) && !Files.isReadable(trustedDirectory)) {
                error(location, Layout.TRUSTED_DIRECTORY + "/ is not readable");
            }
        } catch (IOException e) {
            error(location, "cannot read permissions: " + e.getMessage());
        }
    }

    private void checkValidity(String location, X509Certificate leaf) {
        Date at = Date.from(now);
        try {
            leaf.checkValidity(at);
            long daysLeft =
                    java.time.Duration.between(now, leaf.getNotAfter().toInstant()).toDays();
            if (daysLeft <= EXPIRY_WARNING_DAYS) {
                warning(location, "certificate expires in " + daysLeft + " days");
            } else {
                ok(location, "valid for another " + daysLeft + " days");
            }
        } catch (CertificateExpiredException e) {
            error(location, "certificate expired on " + leaf.getNotAfter().toInstant());
        } catch (CertificateNotYetValidException e) {
            error(location, "certificate is not valid until " + leaf.getNotBefore().toInstant());
        }
    }

    private void checkKeyStrength(String location, PublicKey publicKey) {
        switch (publicKey) {
            case RSAKey rsa -> {
                int bits = rsa.getModulus().bitLength();
                if (bits < MINIMUM_RSA_BITS) {
                    error(location, "RSA key is only " + bits + " bits");
                } else {
                    ok(location, "RSA " + bits + "-bit key");
                }
            }
            case ECKey ec -> {
                int bits = ec.getParams().getCurve().getField().getFieldSize();
                if (bits < MINIMUM_EC_BITS) {
                    error(location, "EC key is only " + bits + " bits");
                } else {
                    ok(location, "EC " + bits + "-bit key");
                }
            }
            default -> warning(location, "unrecognised key type " + publicKey.getAlgorithm());
        }
    }

    private void checkSignatureAlgorithm(String location, List<X509Certificate> chain) {
        for (X509Certificate certificate : chain) {
            String algorithm = certificate.getSigAlgName().toUpperCase(Locale.ROOT);
            if (algorithm.contains("SHA1") || algorithm.contains("MD5")) {
                error(
                        location,
                        "certificate for %s is signed with %s, which is not acceptable"
                                .formatted(certificate.getSubjectX500Principal().getName(), algorithm));
                return;
            }
        }
        ok(location, "signed with " + chain.getFirst().getSigAlgName());
    }

    private void checkExtensions(String location, Scope scope, X509Certificate leaf) {
        if (leaf.getBasicConstraints() != -1) {
            error(location, "leaf certificate is marked as a CA");
        } else {
            ok(location, "not a CA certificate");
        }

        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage == null) {
            warning(location, "no keyUsage extension");
        } else if (!keyUsage[0]) {
            error(location, "keyUsage does not permit digitalSignature");
        } else {
            ok(location, "keyUsage permits digitalSignature");
        }

        List<String> extendedKeyUsage;
        try {
            extendedKeyUsage = leaf.getExtendedKeyUsage();
        } catch (java.security.cert.CertificateParsingException e) {
            error(location, "cannot parse extendedKeyUsage: " + e.getMessage());
            return;
        }
        if (extendedKeyUsage == null) {
            warning(location, "no extendedKeyUsage extension");
            return;
        }
        if (!extendedKeyUsage.contains(Oids.EKU_SERVER_AUTH)) {
            error(location, "extendedKeyUsage is missing serverAuth");
        } else {
            ok(location, "extendedKeyUsage includes serverAuth");
        }
        if (scope.mutualAuthentication()) {
            if (!extendedKeyUsage.contains(Oids.EKU_CLIENT_AUTH)) {
                error(
                        location,
                        "extendedKeyUsage is missing clientAuth, which the %s scope needs because "
                                        .formatted(scope.directoryName())
                                + "client_auth defaults to REQUIRE there");
            } else {
                ok(location, "extendedKeyUsage includes clientAuth");
            }
        }
    }

    private void checkSubjectAlternativeNames(String location, X509Certificate leaf) {
        Collection<List<?>> names;
        try {
            names = leaf.getSubjectAlternativeNames();
        } catch (java.security.cert.CertificateParsingException e) {
            error(location, "cannot parse subjectAlternativeName: " + e.getMessage());
            return;
        }
        if (names == null || names.isEmpty()) {
            error(
                    location,
                    "no subjectAlternativeName — hostname verification is on by default from "
                            + "Neo4j 2025.01 and will reject this certificate");
            return;
        }
        Set<String> present = new LinkedHashSet<>();
        for (List<?> entry : names) {
            // Each entry is [type, value]; type 2 is dNSName and type 7 is iPAddress.
            present.add(String.valueOf(entry.get(1)));
        }
        ok(location, "subjectAlternativeName covers " + String.join(", ", present));

        String commonName = commonNameOf(leaf);
        if (commonName != null && !present.contains(commonName)) {
            warning(
                    location,
                    "common name '%s' is not in the subjectAlternativeName, so clients that check "
                                    .formatted(commonName)
                            + "the SAN will not match it");
        }
    }

    private void checkPrivateKey(
            String location, Path keyFile, String nodeName, PublicKey certificateKey) {
        try {
            PrivateKey privateKey = PemFiles.readPrivateKey(keyFile, passwords.forSubject(nodeName));
            ok(location, "private key decrypts");
            if (PemFiles.matches(privateKey, certificateKey, random)) {
                ok(location, "private key matches the certificate");
            } else {
                error(location, "private key does not match the certificate");
            }
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            error(location, "private key: " + e.getMessage());
        }
    }

    private void checkChain(String location, List<X509Certificate> chain, Path trustedDirectory) {
        List<X509Certificate> anchors;
        try {
            anchors = readTrustAnchors(trustedDirectory);
        } catch (IOException | GeneralSecurityException e) {
            error(location, "cannot read " + Layout.TRUSTED_DIRECTORY + "/: " + e.getMessage());
            return;
        }
        if (anchors.isEmpty()) {
            error(location, Layout.TRUSTED_DIRECTORY + "/ holds no certificates, so no peer can be trusted");
            return;
        }

        X509Certificate leaf = chain.getFirst();
        if (isSelfSigned(leaf)) {
            // A self-signed leaf cannot be validated as a path, because the only certificate in
            // the path is also the trust anchor. Checking that it is present in trusted/ and that
            // its self-signature holds is the equivalent test.
            boolean trusted = anchors.stream().anyMatch(anchor -> anchor.equals(leaf));
            if (trusted) {
                ok(location, "self-signed certificate is present in " + Layout.TRUSTED_DIRECTORY + "/");
            } else {
                error(
                        location,
                        "self-signed certificate is not in its own "
                                + Layout.TRUSTED_DIRECTORY
                                + "/, so this node would not trust itself");
            }
            ok(location, Layout.TRUSTED_DIRECTORY + "/ holds " + anchors.size() + " peer certificate(s)");
            return;
        }

        try {
            Set<java.security.cert.TrustAnchor> trustAnchors = new LinkedHashSet<>();
            for (X509Certificate anchor : anchors) {
                trustAnchors.add(new java.security.cert.TrustAnchor(anchor, null));
            }
            CertPath path = CertificateFactory.getInstance("X.509").generateCertPath(chain);
            PKIXParameters parameters = new PKIXParameters(trustAnchors);
            // No CRL or OCSP responder exists for a locally issued private PKI; revoked/ is where
            // an operator would place CRLs for Neo4j itself to consult.
            parameters.setRevocationEnabled(false);
            parameters.setDate(Date.from(now));
            CertPathValidator.getInstance("PKIX").validate(path, parameters);
            ok(
                    location,
                    "chain of %d validates to a trust anchor in %s/"
                            .formatted(chain.size(), Layout.TRUSTED_DIRECTORY));
        } catch (GeneralSecurityException e) {
            error(location, "chain does not validate: " + e.getMessage());
        }
    }

    private List<X509Certificate> readTrustAnchors(Path trustedDirectory)
            throws IOException, GeneralSecurityException {
        if (!Files.isDirectory(trustedDirectory)) {
            throw new IOException("missing " + Layout.TRUSTED_DIRECTORY + "/ directory");
        }
        List<X509Certificate> anchors = new ArrayList<>();
        List<Path> files;
        try (Stream<Path> children = Files.list(trustedDirectory)) {
            files = children.filter(Files::isRegularFile).sorted().toList();
        }
        for (Path file : files) {
            anchors.addAll(PemFiles.readCertificates(file));
        }
        return anchors;
    }

    private static boolean isSelfSigned(X509Certificate certificate) {
        if (!certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            return false;
        }
        try {
            certificate.verify(certificate.getPublicKey());
            return true;
        } catch (GeneralSecurityException notSelfSigned) {
            return false;
        }
    }

    private static String commonNameOf(X509Certificate certificate) {
        // RFC 2253 form, most specific first, so the CN is the leading attribute.
        for (String part : certificate.getSubjectX500Principal().getName().split(",")) {
            String trimmed = part.trim();
            if (trimmed.startsWith("CN=")) {
                return trimmed.substring(3);
            }
        }
        return null;
    }

    private void ok(String location, String message) {
        findings.add(new Finding(Severity.OK, location, message));
    }

    private void warning(String location, String message) {
        findings.add(new Finding(Severity.WARNING, location, message));
    }

    private void error(String location, String message) {
        findings.add(new Finding(Severity.ERROR, location, message));
    }
}
