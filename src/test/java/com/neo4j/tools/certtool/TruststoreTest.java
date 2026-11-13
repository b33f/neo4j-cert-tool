package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.crypto.Truststore;
import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.output.Layout;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Covers the client truststore ({@code client-truststore.p12}): that a run writes it in every
 * trust mode, that a Java client can complete a real TLS handshake through it alone, and that
 * {@code verify} notices when it is missing, corrupt or incomplete.
 */
class TruststoreTest {

    @TempDir
    Path work;

    @Test
    @DisplayName("a ca-mode run writes a truststore holding exactly the CA certificate")
    void caModeTrustsTheRoot() throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(work, "ca");

        var anchors = Truststore.anchors(Layout.clientTruststore(run.outputDirectory()));
        assertEquals(1, anchors.size());
        assertEquals(
                TestBundles.certificates(run.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE))
                        .getFirst(),
                anchors.getFirst());
    }

    @Test
    @DisplayName("a self-signed run writes one anchor per member, under the member's name")
    void selfSignedTrustsEveryMember() throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(work, "self-signed");

        Path truststore = Layout.clientTruststore(run.outputDirectory());
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(truststore)) {
            keyStore.load(in, Truststore.PASSWORD);
        }

        assertEquals(
                // A self-signed certificate is per node per scope, so each member appears once
                // per scope, under a scope-suffixed alias.
                List.of("core1-backup", "core1-bolt", "core1-cluster", "core1-https",
                        "core2-backup", "core2-bolt", "core2-cluster", "core2-https"),
                Collections.list(keyStore.aliases()).stream().sorted().toList(),
                "aliases are the node and scope names");
        for (String node : List.of("core1", "core2")) {
            for (Scope scope : Scope.values()) {
                X509Certificate fromStore =
                        (X509Certificate) keyStore.getCertificate(node + "-" + scope.directoryName());
                assertEquals(
                        TestBundles.certificates(Layout.publicCertificate(run.node(node), scope)),
                        List.of(fromStore),
                        node + "/" + scope.directoryName() + ": the truststore holds the member's own certificate");
            }
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"ca", "self-signed"})
    @DisplayName("the truststore holds only certificate entries and no key material of any kind")
    void holdsOnlyCertificateEntries(String mode) throws Exception {
        TestBundles.twoNodeCluster(work, mode);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in =
                Files.newInputStream(Layout.clientTruststore(work.resolve("out")))) {
            keyStore.load(in, Truststore.PASSWORD);
        }

        // The property that makes the well-known 'changeit' password safe: every entry is a
        // trusted certificate entry, and no alias yields a key. getKey returns null for a
        // certificate entry, so a regression that stored a private or secret key alongside the
        // anchors would fail here.
        List<String> aliases = Collections.list(keyStore.aliases());
        assertFalse(aliases.isEmpty(), "the truststore should not be empty");
        for (String alias : aliases) {
            assertTrue(keyStore.isCertificateEntry(alias), alias + ": must be a trusted certificate entry");
            assertNull(keyStore.getKey(alias, Truststore.PASSWORD), alias + ": no key material");
        }
    }

    @Test
    @DisplayName("an intermediate-mode run trusts the root, as the nodes do")
    void intermediateModeTrustsTheRoot() throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(work, "intermediate");

        var anchors = Truststore.anchors(Layout.clientTruststore(run.outputDirectory()));
        assertEquals(1, anchors.size());
        assertEquals(
                TestBundles.certificates(run.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE))
                        .getFirst(),
                anchors.getFirst());
    }

    @Test
    @DisplayName("a run reusing an existing CA still writes the truststore")
    void reusingAnExistingCaStillWritesOne() throws Exception {
        Path first = Files.createDirectories(work.resolve("first"));
        TestBundles.Run existing = TestBundles.twoNodeCluster(first, "ca");

        TestBundles.Run added = TestBundles.generate(
                Files.createDirectories(work.resolve("second")),
                "--node",
                "core3:core3.example.com",
                "--ca-cert",
                existing.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE).toString(),
                "--ca-key",
                existing.caDirectory().resolve(Layout.CA_KEY_FILE).toString(),
                "--ca-password-file",
                TestBundles.passwordFile(first).toString());

        var anchors = Truststore.anchors(Layout.clientTruststore(added.outputDirectory()));
        assertEquals(1, anchors.size());
        assertEquals(
                TestBundles.certificates(existing.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE))
                        .getFirst(),
                anchors.getFirst(),
                "the reused CA is the anchor, exactly as in the run that created it");
    }

    @Test
    @DisplayName("a Java client trusts a real handshake through the truststore file alone")
    void aJavaClientCompletesAHandshakeThroughIt() throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(work, "ca");

        // The client loads its trust material the way cypher-shell or a driver application does:
        // a PKCS#12 keystore file, the generated password, nothing else.
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (InputStream in =
                Files.newInputStream(Layout.clientTruststore(run.outputDirectory()))) {
            trustStore.load(in, Truststore.PASSWORD);
        }
        TrustManagerFactory trustManagers =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trustStore);
        SSLContext client = SSLContext.getInstance("TLS");
        client.init(null, trustManagers.getTrustManagers(), new SecureRandom());

        var handshake = TestBundles.handshake(
                TestBundles.sslContext(run.node("core1"), Scope.BOLT),
                client,
                "core1.example.com",
                false);

        assertTrue(
                handshake.serverSubject().contains("core1.example.com"),
                "the client authenticated the server: " + handshake.serverSubject());
    }

    @Test
    @DisplayName("verify checks the truststore on a staging root")
    void verifyChecksIt() throws Exception {
        TestBundles.twoNodeCluster(work, "ca");

        TestBundles.Run verified = TestBundles.verify(work);

        assertEquals(Main.EXIT_OK, verified.exitCode(), verified.output());
        assertTrue(verified.output().contains(Layout.CLIENT_TRUSTSTORE_FILE), verified.output());
        assertTrue(verified.output().contains("covers every trust anchor"), verified.output());
    }

    @Test
    @DisplayName("a missing truststore is a warning, not a failure")
    void missingIsOnlyAWarning() throws Exception {
        TestBundles.twoNodeCluster(work, "ca");
        Files.delete(Layout.clientTruststore(work.resolve("out")));

        TestBundles.Run verified = TestBundles.verify(work);

        assertEquals(Main.EXIT_OK, verified.exitCode(), verified.output());
        assertTrue(verified.stderr().contains("client-truststore.p12"), verified.output());
        assertTrue(verified.stderr().contains("not present"), verified.output());
    }

    @Test
    @DisplayName("a corrupt truststore fails verification")
    void corruptFails() throws Exception {
        TestBundles.twoNodeCluster(work, "ca");
        Files.write(
                Layout.clientTruststore(work.resolve("out")),
                "not a keystore".getBytes(StandardCharsets.UTF_8));

        TestBundles.Run verified = TestBundles.verify(work);

        assertEquals(Main.EXIT_FAILURE, verified.exitCode(), verified.output());
        assertTrue(verified.stderr().contains("does not load"), verified.output());
    }

    @Test
    @DisplayName("a truststore missing an anchor the bundles trust fails verification")
    void incompleteFails() throws Exception {
        // Two nodes sharing one CA: the truststore must cover that CA. A store holding only a
        // leaf certificate represents the mistake of trusting the leaf instead.
        TestBundles.Run run = TestBundles.twoNodeCluster(work, "ca");
        X509Certificate leaf = TestBundles.certificates(
                        run.node("core1")
                                .resolve(Layout.CERTIFICATES_DIRECTORY)
                                .resolve("bolt")
                                .resolve(Layout.PUBLIC_CERTIFICATE_FILE))
                .getFirst();
        byte[] wrong = Truststore.pkcs12(new LinkedHashMap<>(Map.of("oops", leaf)));
        Files.write(Layout.clientTruststore(work.resolve("out")), wrong);

        TestBundles.Run verified = TestBundles.verify(work);

        assertEquals(Main.EXIT_FAILURE, verified.exitCode(), verified.output());
        assertTrue(verified.stderr().contains("does not cover"), verified.output());
    }
}
