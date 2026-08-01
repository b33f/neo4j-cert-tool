package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.crypto.Der;
import com.neo4j.tools.certtool.crypto.DistinguishedName;
import com.neo4j.tools.certtool.crypto.Extensions;
import com.neo4j.tools.certtool.crypto.Oids;
import com.neo4j.tools.certtool.crypto.PemFiles;
import com.neo4j.tools.certtool.crypto.SignatureAlgorithm;
import com.neo4j.tools.certtool.crypto.X509Builder;
import com.neo4j.tools.certtool.model.NameConstraints;
import com.neo4j.tools.certtool.model.NodeSpec;
import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.output.Layout;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Covers the name constraints placed on a generated certificate authority.
 *
 * <p>A CA that can sign anything is a liability once it is trusted: whoever holds the key can mint a
 * certificate for any name at all. Constraining it bounds the damage to the deployment it was made
 * for.
 */
class NameConstraintsTest {

    private final SecureRandom random = new SecureRandom();

    @Nested
    @DisplayName("what gets derived")
    class Derivation {

        @ParameterizedTest
        @CsvSource({
            // A node name is constrained to its parent, so siblings can be added later.
            "core1.example.com, example.com",
            "db.internal.example.com, internal.example.com",
            "'*.example.com', example.com",
            // Two labels are kept whole: stripping example.com to com would permit a whole TLD.
            "example.com, example.com",
            "localhost, localhost"
        })
        void dnsNamesAreConstrainedToTheirParent(String name, String expected) {
            assertEquals(expected, NameConstraints.parentDomain(name));
        }

        @Test
        @DisplayName("a cluster in one domain yields one subtree")
        void oneDomainOneSubtree() {
            var constraints = NameConstraints.deriveFrom(
                    List.of(
                            NodeSpec.parse("core1:core1.example.com"),
                            NodeSpec.parse("core2:core2.example.com"),
                            NodeSpec.parse("core3:core3.example.com")),
                    List.of(),
                    List.of());

            assertEquals(List.of("example.com"), constraints.permittedDns());
        }

        @Test
        @DisplayName("a broader subtree absorbs one beneath it")
        void subtreesCollapse() {
            var constraints = NameConstraints.deriveFrom(
                    List.of(
                            NodeSpec.parse("a:core1.db.example.com"), // -> db.example.com
                            NodeSpec.parse("b:core2.example.com")), // -> example.com
                    List.of(),
                    List.of());

            assertEquals(List.of("example.com"), constraints.permittedDns());
        }

        @ParameterizedTest
        @CsvSource({
            // A private address is widened to its whole block, so a sibling node can be added.
            "10.0.0.11, 10.0.0.0/8",
            "192.168.1.5, 192.168.0.0/16",
            "172.16.4.4, 172.16.0.0/12",
            "127.0.0.1, 127.0.0.0/8",
            // A routable address gets no room: it is constrained to exactly itself.
            "8.8.8.8, 8.8.8.8/32"
        })
        void addressesAreConstrainedToTheirBlock(String address, String expected) {
            var constraints = NameConstraints.deriveFrom(
                    List.of(NodeSpec.parse("n:host.example.com," + address)), List.of(), List.of());

            assertEquals(List.of(expected), constraints.permittedIps().stream().map(Object::toString).toList());
        }

        @Test
        @DisplayName("with no addresses at all, every address is excluded")
        void addressesAreExcludedWhenUnused() {
            // RFC 5280 only constrains name types that appear, so saying nothing about IP would
            // leave the CA free to certify any address it liked.
            var constraints =
                    NameConstraints.deriveFrom(List.of(NodeSpec.parse("n:host.example.com")), List.of(), List.of());

            assertTrue(constraints.excludeAllIpAddresses());
            assertTrue(constraints.permittedIps().isEmpty());
        }

        @Test
        @DisplayName("--permit-dns and --permit-ip widen the constraint")
        void extraSubtreesAreHonoured() {
            var constraints = NameConstraints.deriveFrom(
                    List.of(NodeSpec.parse("n:core1.example.com")),
                    List.of("other.example.org"),
                    List.of("192.168.0.0/16"));

            assertTrue(constraints.permittedDns().contains("example.com"));
            assertTrue(constraints.permittedDns().contains("other.example.org"));
            assertEquals(List.of("192.168.0.0/16"), constraints.permittedIps().stream().map(Object::toString).toList());
            assertFalse(constraints.excludeAllIpAddresses());
        }

        @Test
        @DisplayName("the constraint knows what it permits")
        void permitsAnswersCorrectly() {
            var constraints = NameConstraints.deriveFrom(
                    List.of(NodeSpec.parse("n:core1.example.com,10.0.0.11")), List.of(), List.of());

            assertTrue(constraints.permits("core9.example.com"));
            assertTrue(constraints.permits("example.com"));
            assertTrue(constraints.permits("10.0.0.99"));
            assertFalse(constraints.permits("google.com"));
            assertFalse(constraints.permits("example.com.evil.net"));
            assertFalse(constraints.permits("8.8.8.8"));
        }
    }

    @Nested
    @DisplayName("what ends up in the certificate")
    class Encoding {

        @Test
        @DisplayName("the CA carries a critical nameConstraints extension")
        void caIsConstrained(@TempDir Path work) throws Exception {
            TestBundles.Run run = TestBundles.twoNodeCluster(work, "ca");
            X509Certificate ca = TestBundles.certificates(
                            run.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE))
                    .getFirst();

            assertNotNull(ca.getExtensionValue(Oids.NAME_CONSTRAINTS), "the CA must be constrained");
            assertTrue(
                    ca.getCriticalExtensionOIDs().contains(Oids.NAME_CONSTRAINTS),
                    "RFC 5280 requires nameConstraints to be critical");

            // The shared fixture's nodes declare core1.example.com, localhost and 127.0.0.1, so
            // both DNS subtrees are permitted and nothing else is.
            assertEquals(List.of("example.com", "localhost"), permittedDns(ca));
        }

        @Test
        @DisplayName("the intermediate is constrained too, where a validator will always see it")
        void intermediateIsConstrained(@TempDir Path work) throws Exception {
            TestBundles.Run run = TestBundles.twoNodeCluster(work, "intermediate");

            for (String file : List.of(Layout.CA_CERTIFICATE_FILE, Layout.INTERMEDIATE_CERTIFICATE_FILE)) {
                X509Certificate ca =
                        TestBundles.certificates(run.caDirectory().resolve(file)).getFirst();
                assertEquals(
                        List.of("example.com", "localhost"), permittedDns(ca), file + " must be constrained");
            }
        }

        @Test
        @DisplayName("leaf certificates are not constrained; the limit belongs on the CA")
        void leavesAreNotConstrained(@TempDir Path work) throws Exception {
            TestBundles.Run run = TestBundles.twoNodeCluster(work, "ca");
            X509Certificate leaf = TestBundles.certificates(
                            Layout.publicCertificate(run.node("core1"), Scope.BOLT))
                    .getFirst();

            assertNull(leaf.getExtensionValue(Oids.NAME_CONSTRAINTS));
        }

        @Test
        @DisplayName("--no-name-constraints leaves the CA unconstrained")
        void constraintsCanBeSwitchedOff(@TempDir Path work) throws Exception {
            TestBundles.Run run = TestBundles.twoNodeCluster(work, "ca", "--no-name-constraints");
            X509Certificate ca = TestBundles.certificates(
                            run.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE))
                    .getFirst();

            assertNull(ca.getExtensionValue(Oids.NAME_CONSTRAINTS));
        }

        @Test
        @DisplayName("self-signed mode has no CA to constrain")
        void selfSignedModeIsUnaffected(@TempDir Path work) throws Exception {
            TestBundles.Run run = TestBundles.twoNodeCluster(work, "self-signed");
            X509Certificate leaf = TestBundles.certificates(
                            Layout.publicCertificate(run.node("core1"), Scope.BOLT))
                    .getFirst();

            assertNull(leaf.getExtensionValue(Oids.NAME_CONSTRAINTS));
        }
    }

    @Nested
    @DisplayName("enforcement")
    class Enforcement {

        @Test
        @DisplayName("a forged certificate is rejected when the constrained CA is inside the path")
        void constraintIsEnforcedInsideThePath(@TempDir Path work) throws Exception {
            // Intermediate mode: the constrained CA is not the anchor, so a validator processes its
            // extensions as part of path validation.
            TestBundles.Run run = TestBundles.twoNodeCluster(work, "intermediate");
            X509Certificate root = TestBundles.certificates(
                            run.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE))
                    .getFirst();
            X509Certificate intermediate = TestBundles.certificates(
                            run.caDirectory().resolve(Layout.INTERMEDIATE_CERTIFICATE_FILE))
                    .getFirst();
            PrivateKey intermediateKey = PemFiles.readPrivateKey(
                    run.caDirectory().resolve(Layout.INTERMEDIATE_KEY_FILE),
                    TestBundles.PASSWORD.toCharArray());

            X509Certificate forged = forge("google.com", intermediate, intermediateKey);
            // The signature is genuine — this is what a stolen CA key would produce.
            forged.verify(intermediate.getPublicKey());

            String outcome = validate(List.of(forged, intermediate), root);
            assertTrue(
                    outcome.startsWith("REJECTED"),
                    "a certificate for google.com must not validate: " + outcome);
            assertTrue(outcome.contains("name constraints"), outcome);

            // And a legitimate certificate still validates through the same path.
            X509Certificate genuine = TestBundles.certificates(
                            Layout.publicCertificate(run.node("core1"), Scope.BOLT))
                    .getFirst();
            assertEquals("ACCEPTED", validate(List.of(genuine, intermediate), root));
        }

        @Test
        @DisplayName("the JDK does not enforce constraints carried by a trust anchor")
        void anchorConstraintsAreNotEnforcedByTheJdk(@TempDir Path work) throws Exception {
            // Documented behaviour rather than a wish: RFC 5280 path validation starts below the
            // anchor, so a root's own extensions are not processed. OpenSSL and the OS trust stores
            // do enforce them, which is where the constraint earns its keep — but the JDK, and so
            // Neo4j, does not. This test exists so that if a future JDK changes, we find out.
            TestBundles.Run run = TestBundles.twoNodeCluster(work, "ca");
            X509Certificate ca = TestBundles.certificates(
                            run.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE))
                    .getFirst();
            PrivateKey caKey = PemFiles.readPrivateKey(
                    run.caDirectory().resolve(Layout.CA_KEY_FILE), TestBundles.PASSWORD.toCharArray());

            X509Certificate forged = forge("google.com", ca, caKey);
            String outcome = validate(List.of(forged), ca);

            assertEquals(
                    "ACCEPTED",
                    outcome,
                    "If this now fails, the JDK has started enforcing anchor name constraints — "
                            + "update the README, which currently says it does not");
        }
    }

    @Nested
    @DisplayName("issuing from a constrained CA")
    class Reuse {

        @Test
        @DisplayName("a node inside the constraint can still be added later")
        void permittedNodesAreIssued(@TempDir Path work) throws Exception {
            TestBundles.Run first = TestBundles.twoNodeCluster(work, "ca");

            Path later = Files.createDirectory(work.resolve("later"));
            TestBundles.Run added = TestBundles.generate(
                    later,
                    "--node", "core9:core9.example.com,10.0.0.99",
                    "--ca-cert", first.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE).toString(),
                    "--ca-key", first.caDirectory().resolve(Layout.CA_KEY_FILE).toString(),
                    "--ca-password-file", TestBundles.passwordFile(work).toString());

            assertTrue(Files.isRegularFile(Layout.publicCertificate(added.node("core9"), Scope.BOLT)));
        }

        @Test
        @DisplayName("a node outside the constraint is refused, with the reason")
        void forbiddenNodesAreRefused(@TempDir Path work) throws Exception {
            TestBundles.Run first = TestBundles.twoNodeCluster(work, "ca");

            Path later = Files.createDirectory(work.resolve("later"));
            TestBundles.Run attempt = TestBundles.run(
                    later,
                    "--node", "evil:google.com",
                    "--ca-cert", first.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE).toString(),
                    "--ca-key", first.caDirectory().resolve(Layout.CA_KEY_FILE).toString(),
                    "--ca-password-file", TestBundles.passwordFile(work).toString());

            assertEquals(Main.EXIT_FAILURE, attempt.exitCode(), attempt.output());
            assertTrue(attempt.stderr().contains("name constrained"), attempt.stderr());
            assertTrue(attempt.stderr().contains("google.com"), attempt.stderr());
            assertTrue(attempt.stderr().contains("example.com"), attempt.stderr());
            // Nothing should have been written for a run that cannot produce usable certificates.
            assertFalse(Files.exists(later.resolve("out").resolve("evil")));
        }
    }

    // --- helpers ---------------------------------------------------------------------------

    /** The permitted DNS subtrees recorded in a certificate. */
    private static List<String> permittedDns(X509Certificate certificate) {
        byte[] value = new Der.Reader(certificate.getExtensionValue(Oids.NAME_CONSTRAINTS))
                .readPrimitive(Der.TAG_OCTET_STRING);
        return Extensions.permittedDnsSubtrees(value);
    }

    /** Signs a certificate for an arbitrary name, as a stolen CA key would. */
    private X509Certificate forge(String name, X509Certificate issuer, PrivateKey issuerKey)
            throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"), random);
        KeyPair keyPair = generator.generateKeyPair();

        return new X509Builder(random)
                .subject(DistinguishedName.builder().commonName(name).build())
                .issuer(DistinguishedName.ofEncoded(
                        issuer.getSubjectX500Principal().getEncoded(),
                        issuer.getSubjectX500Principal().getName()))
                .publicKey(keyPair.getPublic())
                .validity(Instant.now(), 30)
                .addExtension(Extensions.basicConstraintsEndEntity())
                .addExtension(Extensions.keyUsage(Extensions.KeyUsage.DIGITAL_SIGNATURE))
                .addExtension(Extensions.extendedKeyUsage(Oids.EKU_SERVER_AUTH))
                .addExtension(Extensions.subjectAlternativeName(List.of(name)))
                .signWith(issuerKey, SignatureAlgorithm.forSigningKey(issuerKey));
    }

    private static String validate(List<X509Certificate> chain, X509Certificate anchor) {
        try {
            CertPath path = CertificateFactory.getInstance("X.509")
                    .generateCertPath(new ArrayList<Certificate>(chain));
            PKIXParameters parameters = new PKIXParameters(Set.of(new TrustAnchor(anchor, null)));
            parameters.setRevocationEnabled(false);
            CertPathValidator.getInstance("PKIX").validate(path, parameters);
            return "ACCEPTED";
        } catch (Exception rejected) {
            return "REJECTED: " + rejected.getMessage();
        }
    }
}
