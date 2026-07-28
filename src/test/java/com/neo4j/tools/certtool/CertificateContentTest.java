package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.crypto.Oids;
import com.neo4j.tools.certtool.crypto.PemFiles;
import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.output.Layout;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Checks the contents of the certificates against what Neo4j and RFC 5280 require. */
class CertificateContentTest {

    private static X509Certificate leaf(TestBundles.Run run, String node, Scope scope)
            throws Exception {
        return TestBundles.certificates(Layout.publicCertificate(run.node(node), scope)).getFirst();
    }

    @ParameterizedTest
    @EnumSource(Scope.class)
    @DisplayName("every scope gets a version 3 certificate covering its declared names")
    void everyScopeIsPopulated(Scope scope, @TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        X509Certificate certificate = leaf(run, "core1", scope);

        assertEquals(3, certificate.getVersion());
        assertTrue(
                certificate.getSubjectX500Principal().getName().contains("CN=core1.example.com"),
                certificate.getSubjectX500Principal().getName());
        assertEquals(
                Set.of("core1.example.com", "localhost", "127.0.0.1"),
                subjectAlternativeNames(certificate));
    }

    @ParameterizedTest
    @EnumSource(Scope.class)
    @DisplayName("extended key usage matches what the scope's client_auth default needs")
    void extendedKeyUsageMatchesTheScope(Scope scope, @TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        List<String> extendedKeyUsage = leaf(run, "core1", scope).getExtendedKeyUsage();

        assertTrue(extendedKeyUsage.contains(Oids.EKU_SERVER_AUTH), "serverAuth is always needed");
        if (scope.mutualAuthentication()) {
            // cluster and backup default to client_auth=REQUIRE, so the certificate is presented
            // as a client certificate too.
            assertTrue(
                    extendedKeyUsage.contains(Oids.EKU_CLIENT_AUTH),
                    scope + " needs clientAuth: " + extendedKeyUsage);
        } else {
            assertFalse(
                    extendedKeyUsage.contains(Oids.EKU_CLIENT_AUTH),
                    scope + " does not need clientAuth: " + extendedKeyUsage);
        }
    }

    @Test
    @DisplayName("leaf certificates are not CA certificates")
    void leavesAreNotCas(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        for (Scope scope : Scope.values()) {
            X509Certificate certificate = leaf(run, "core1", scope);
            assertEquals(-1, certificate.getBasicConstraints(), scope + " must not be a CA");
            // basicConstraints is marked critical, so a validator cannot ignore it.
            assertTrue(
                    certificate.getCriticalExtensionOIDs().contains(Oids.BASIC_CONSTRAINTS),
                    scope + " basicConstraints must be critical");
        }
    }

    @Test
    @DisplayName("key usage is critical and permits digital signatures")
    void keyUsageIsCorrect(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        X509Certificate certificate = leaf(run, "core1", Scope.BOLT);
        boolean[] keyUsage = certificate.getKeyUsage();

        assertTrue(keyUsage[0], "digitalSignature");
        assertFalse(keyUsage[5], "keyCertSign must not be set on a leaf");
        assertFalse(keyUsage[6], "cRLSign must not be set on a leaf");
        assertTrue(certificate.getCriticalExtensionOIDs().contains(Oids.KEY_USAGE));
    }

    @Test
    @DisplayName("RSA leaves additionally permit keyEncipherment")
    void rsaLeavesPermitKeyEncipherment(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca", "--key-type", "rsa-3072");

        boolean[] keyUsage = leaf(run, "core1", Scope.BOLT).getKeyUsage();

        assertTrue(keyUsage[0], "digitalSignature");
        assertTrue(keyUsage[2], "keyEncipherment, for TLS 1.2 RSA key transport");
    }

    @Test
    @DisplayName("EC leaves do not claim keyEncipherment, which they cannot do")
    void ecLeavesDoNotClaimKeyEncipherment(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        assertFalse(leaf(run, "core1", Scope.BOLT).getKeyUsage()[2]);
    }

    @Test
    @DisplayName("key identifiers link each leaf to its issuer")
    void keyIdentifiersLinkTheChain(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        X509Certificate certificate = leaf(run, "core1", Scope.BOLT);
        X509Certificate ca = TestBundles.certificates(
                        run.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE))
                .getFirst();

        assertTrue(certificate.getExtensionValue(Oids.SUBJECT_KEY_IDENTIFIER) != null);
        assertTrue(certificate.getExtensionValue(Oids.AUTHORITY_KEY_IDENTIFIER) != null);
        assertEquals(
                certificate.getIssuerX500Principal(),
                ca.getSubjectX500Principal(),
                "the leaf's issuer name must be exactly the CA's subject name");
    }

    @Test
    @DisplayName("the CA can sign certificates and nothing else")
    void theCaIsConstrained(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        X509Certificate ca = TestBundles.certificates(
                        run.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE))
                .getFirst();

        // pathLenConstraint of 0: this CA may issue end-entity certificates but no further CAs.
        assertEquals(0, ca.getBasicConstraints());
        assertTrue(ca.getKeyUsage()[5], "keyCertSign");
        assertTrue(ca.getKeyUsage()[6], "cRLSign");
        assertFalse(ca.getKeyUsage()[0], "a CA that only signs certificates needs no digitalSignature");
        assertEquals(ca.getSubjectX500Principal(), ca.getIssuerX500Principal(), "self-signed root");
        ca.verify(ca.getPublicKey());
    }

    @Test
    @DisplayName("intermediate mode produces a root that may issue one level of CA")
    void intermediateModeConstrainsBothTiers(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "intermediate");

        X509Certificate root = TestBundles.certificates(
                        run.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE))
                .getFirst();
        X509Certificate intermediate = TestBundles.certificates(
                        run.caDirectory().resolve(Layout.INTERMEDIATE_CERTIFICATE_FILE))
                .getFirst();

        assertEquals(1, root.getBasicConstraints(), "the root may sign one CA below it");
        assertEquals(0, intermediate.getBasicConstraints(), "the intermediate signs leaves only");
        intermediate.verify(root.getPublicKey());

        List<X509Certificate> chain =
                TestBundles.certificates(Layout.publicCertificate(run.node("core1"), Scope.BOLT));
        assertEquals(2, chain.size(), "public.crt must carry the intermediate with the leaf");
        assertEquals(intermediate.getSubjectX500Principal(), chain.get(1).getSubjectX500Principal());
        chain.getFirst().verify(intermediate.getPublicKey());
    }

    @Test
    @DisplayName("self-signed mode cross-trusts every member and creates no CA")
    void selfSignedModeCrossTrusts(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "self-signed");

        assertFalse(Files.exists(run.caDirectory()), "self-signed mode must not create a CA");

        X509Certificate core1 = leaf(run, "core1", Scope.CLUSTER);
        assertEquals(core1.getSubjectX500Principal(), core1.getIssuerX500Principal());
        core1.verify(core1.getPublicKey());

        // Each node's trusted/ holds every member's certificate, its own included.
        assertEquals(
                List.of("core1.crt", "core2.crt"),
                TestBundles.trustedFileNames(run.node("core1"), Scope.CLUSTER));
        assertEquals(
                List.of("core1.crt", "core2.crt"),
                TestBundles.trustedFileNames(run.node("core2"), Scope.CLUSTER));
    }

    @Test
    @DisplayName("ca mode puts only the root in trusted/")
    void caModeTrustsOnlyTheRoot(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        for (Scope scope : Scope.values()) {
            assertEquals(
                    List.of("root-ca.crt"),
                    TestBundles.trustedFileNames(run.node("core1"), scope),
                    "adding a node must not require touching existing members' trusted/");
        }
    }

    @Test
    @DisplayName("every node and scope gets its own key pair")
    void keysAreNeverShared(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        List<String> publicKeys = new ArrayList<>();
        for (String node : List.of("core1", "core2")) {
            for (Scope scope : Scope.values()) {
                publicKeys.add(
                        java.util.HexFormat.of()
                                .formatHex(leaf(run, node, scope).getPublicKey().getEncoded()));
            }
        }

        assertEquals(
                publicKeys.size(),
                new HashSet<>(publicKeys).size(),
                "a key compromised on one channel must not extend to the others");
    }

    @Test
    @DisplayName("serial numbers are unpredictable and positive")
    void serialNumbersAreRandom(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        Set<java.math.BigInteger> serials = new HashSet<>();
        for (String node : List.of("core1", "core2")) {
            for (Scope scope : Scope.values()) {
                java.math.BigInteger serial = leaf(run, node, scope).getSerialNumber();
                assertEquals(1, serial.signum(), "RFC 5280 requires a positive serial number");
                assertTrue(serial.bitLength() > 64, "at least 64 bits of entropy: " + serial);
                serials.add(serial);
            }
        }
        assertEquals(8, serials.size(), "serial numbers must not repeat");
    }

    @Test
    @DisplayName("validity is backdated slightly and runs for the requested number of days")
    void validityHonoursTheRequestedLifetime(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca", "--validity-days", "30");

        X509Certificate certificate = leaf(run, "core1", Scope.BOLT);
        var notBefore = certificate.getNotBefore().toInstant();
        var notAfter = certificate.getNotAfter().toInstant();

        long days = Duration.between(notBefore, notAfter).toDays();
        assertEquals(30, days, "30 days plus the clock-skew backdate, truncated to whole days");
        assertTrue(
                notBefore.isBefore(java.time.Instant.now()),
                "notBefore is backdated so a peer with a slightly slow clock still accepts it");
    }

    @Test
    @DisplayName("CA certificates outlive the leaves they issue")
    void caOutlivesItsLeaves(@TempDir Path directory) throws Exception {
        TestBundles.Run run =
                TestBundles.twoNodeCluster(directory, "ca", "--ca-validity-days", "1000");

        X509Certificate ca = TestBundles.certificates(
                        run.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE))
                .getFirst();
        X509Certificate certificate = leaf(run, "core1", Scope.BOLT);

        assertTrue(ca.getNotAfter().after(certificate.getNotAfter()));
        assertEquals(
                1000,
                Duration.between(ca.getNotBefore().toInstant(), ca.getNotAfter().toInstant()).toDays());
    }

    @Test
    @DisplayName("certificates are signed with a SHA-2 family digest")
    void signaturesUseModernDigests(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        assertEquals("SHA256withECDSA", leaf(run, "core1", Scope.BOLT).getSigAlgName());

        TestBundles.Run p384 = TestBundles.twoNodeCluster(
                Files.createDirectory(directory.resolve("p384")), "ca", "--key-type", "ec-p384");
        assertEquals(
                "SHA384withECDSA",
                leaf(p384, "core1", Scope.BOLT).getSigAlgName(),
                "the digest should match the curve strength");
    }

    @Test
    @DisplayName("subject naming attributes are carried through")
    void subjectAttributesAreCarriedThrough(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(
                directory,
                "ca",
                "--organisation",
                "Example Ltd",
                "--organisational-unit",
                "Platform",
                "--country",
                "gb",
                "--locality",
                "London");

        String subject = leaf(run, "core1", Scope.CLUSTER).getSubjectX500Principal().getName();

        assertTrue(subject.contains("O=Example Ltd"), subject);
        assertTrue(subject.contains("C=GB"), "country is upper-cased: " + subject);
        assertTrue(subject.contains("L=London"), subject);
        // The scope is appended to the unit so it is obvious which policy a certificate serves.
        assertTrue(subject.contains("OU=Platform cluster"), subject);
    }

    @ParameterizedTest
    @ValueSource(strings = {"bolt", "bolt,https", "cluster,backup"})
    @DisplayName("only the requested scopes are written")
    void onlyRequestedScopesAreWritten(String scopes, @TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca", "--scopes", scopes);

        Set<String> requested = Set.of(scopes.split(","));
        for (Scope scope : Scope.values()) {
            boolean present = Files.isDirectory(Layout.scope(run.node("core1"), scope));
            assertEquals(requested.contains(scope.directoryName()), present, scope + " present");
        }
    }

    @Test
    @DisplayName("an IP-only node still gets a usable certificate")
    void ipOnlyNodesAreSupported(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.generate(directory, "--node", "core1:10.1.2.3,::1");

        X509Certificate certificate = leaf(run, "core1", Scope.BOLT);

        assertEquals(Set.of("10.1.2.3", "0:0:0:0:0:0:0:1"), subjectAlternativeNames(certificate));
        // With no DNS name available the first address becomes the common name.
        assertTrue(certificate.getSubjectX500Principal().getName().contains("CN=10.1.2.3"));
    }

    @Test
    @DisplayName("private keys on disk belong to the certificates beside them")
    void privateKeysMatchTheirCertificates(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        var random = new java.security.SecureRandom();
        for (Scope scope : Scope.values()) {
            var privateKey = PemFiles.readPrivateKey(
                    Layout.privateKey(run.node("core1"), scope), TestBundles.PASSWORD.toCharArray());
            assertTrue(
                    PemFiles.matches(privateKey, leaf(run, "core1", scope).getPublicKey(), random),
                    scope + ": private.key must match public.crt");
        }
    }

    @Test
    @DisplayName("keys on disk are encrypted, not merely stored")
    void keysOnDiskAreEncrypted(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        String key = Files.readString(Layout.privateKey(run.node("core1"), Scope.BOLT));

        assertTrue(key.startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----"), key.lines().findFirst().orElse(""));
        assertFalse(key.contains("BEGIN PRIVATE KEY"), "an unencrypted key must never be written");
        assertFalse(key.contains("BEGIN EC PRIVATE KEY"), "PKCS#1 is deprecated by Neo4j");
    }

    @Test
    @DisplayName("two nodes' certificates differ even with identical names")
    void nodesAreDistinct(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        assertNotEquals(
                leaf(run, "core1", Scope.BOLT).getSerialNumber(),
                leaf(run, "core2", Scope.BOLT).getSerialNumber());
    }

    /** The SAN entries as plain strings, whatever their type. */
    private static Set<String> subjectAlternativeNames(X509Certificate certificate)
            throws Exception {
        Set<String> names = new java.util.LinkedHashSet<>();
        for (List<?> entry : certificate.getSubjectAlternativeNames()) {
            names.add(String.valueOf(entry.get(1)));
        }
        return names;
    }

    @Test
    @DisplayName("notBefore is truncated to whole seconds, as DER time requires")
    void timesAreWholeSeconds(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        var notBefore = leaf(run, "core1", Scope.BOLT).getNotBefore().toInstant();
        assertEquals(notBefore.truncatedTo(ChronoUnit.SECONDS), notBefore);
    }
}
