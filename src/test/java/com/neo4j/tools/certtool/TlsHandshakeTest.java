package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.model.Scope;
import java.nio.file.Path;
import java.util.List;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Uses the generated material to complete real TLS handshakes.
 *
 * <p>Inspecting certificate fields proves the encoding is right; only a handshake proves the
 * material is usable. These tests stand in for what Neo4j itself does with the files: load an
 * encrypted private key with its password, present a chain, and validate the peer against the
 * {@code trusted/} directory with hostname verification enabled.
 */
class TlsHandshakeTest {

    @Test
    @DisplayName("cluster scope: two members authenticate each other")
    void clusterMembersAuthenticateEachOther(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        SSLContext server = TestBundles.sslContext(run.node("core1"), Scope.CLUSTER);
        SSLContext client = TestBundles.sslContext(run.node("core2"), Scope.CLUSTER);

        // client_auth defaults to REQUIRE for the cluster scope, so both sides present a
        // certificate and both must validate.
        TestBundles.Handshake handshake = TestBundles.handshake(server, client, "core1.example.com", true);

        assertTrue(
                handshake.serverSubject().contains("CN=core1.example.com"),
                "client saw server subject " + handshake.serverSubject());
        assertTrue(
                handshake.clientSubject().contains("CN=core2.example.com"),
                "server saw client subject " + handshake.clientSubject());
        assertTrue(
                handshake.protocol().equals("TLSv1.3") || handshake.protocol().equals("TLSv1.2"),
                "negotiated " + handshake.protocol());
    }

    @Test
    @DisplayName("backup scope: mutual authentication also works")
    void backupScopeRequiresClientAuthentication(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        TestBundles.Handshake handshake = TestBundles.handshake(
                TestBundles.sslContext(run.node("core1"), Scope.BACKUP),
                TestBundles.sslContext(run.node("core2"), Scope.BACKUP),
                "core1.example.com",
                true);

        assertTrue(handshake.clientSubject().contains("CN=core2.example.com"));
    }

    @Test
    @DisplayName("bolt scope: a driver with no client certificate connects")
    void boltClientsNeedNoCertificate(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        // A driver holds only the CA certificate; client_auth is NONE for bolt.
        SSLContext driver = TestBundles.trustOnlyContext(run.node("core1"), Scope.BOLT);

        TestBundles.Handshake handshake = TestBundles.handshake(
                TestBundles.sslContext(run.node("core1"), Scope.BOLT), driver, "core1.example.com", false);

        assertTrue(handshake.serverSubject().contains("CN=core1.example.com"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"core1.example.com", "localhost", "127.0.0.1"})
    @DisplayName("every name in the subjectAlternativeName passes hostname verification")
    void everySubjectAlternativeNameIsAccepted(String name, @TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        TestBundles.Handshake handshake = TestBundles.handshake(
                TestBundles.sslContext(run.node("core1"), Scope.BOLT),
                TestBundles.trustOnlyContext(run.node("core1"), Scope.BOLT),
                name,
                false);

        assertTrue(handshake.serverSubject().contains("CN=core1.example.com"));
    }

    @Test
    @DisplayName("an IP-only certificate passes hostname verification when connecting by address")
    void ipOnlyCertificatesWork(@TempDir Path directory) throws Exception {
        // A cluster addressed purely by IP, with no DNS names anywhere. Hostname verification is
        // still on, so the address has to match an iPAddress entry in the SAN.
        String loopback = java.net.InetAddress.getLoopbackAddress().getHostAddress();
        TestBundles.Run run = TestBundles.generate(
                directory,
                "--node", "n1:" + loopback,
                "--node", "n2:" + loopback,
                "--scopes", "bolt,cluster");

        TestBundles.Handshake bolt = TestBundles.handshake(
                TestBundles.sslContext(run.node("n1"), Scope.BOLT),
                TestBundles.trustOnlyContext(run.node("n1"), Scope.BOLT),
                loopback,
                false);
        assertTrue(bolt.serverSubject().contains("CN=" + loopback), bolt.serverSubject());

        // And mutual authentication, which is what the cluster scope needs.
        TestBundles.Handshake cluster = TestBundles.handshake(
                TestBundles.sslContext(run.node("n1"), Scope.CLUSTER),
                TestBundles.sslContext(run.node("n2"), Scope.CLUSTER),
                loopback,
                true);
        assertTrue(cluster.clientSubject().contains("CN=" + loopback), cluster.clientSubject());
    }

    @Test
    @DisplayName("an IPv6-only certificate works too")
    void ipv6OnlyCertificatesWork(@TempDir Path directory) throws Exception {
        // Skip where the loopback interface has no IPv6 address to bind.
        org.junit.jupiter.api.Assumptions.assumeTrue(
                hasIpv6Loopback(), "no IPv6 loopback available on this host");

        TestBundles.Run run = TestBundles.generate(
                directory, "--node", "n1:::1", "--scopes", "bolt");

        // The certificate carries ::1; the client binds and connects on the same literal.
        TestBundles.Handshake handshake = TestBundles.handshake(
                TestBundles.sslContext(run.node("n1"), Scope.BOLT),
                TestBundles.trustOnlyContext(run.node("n1"), Scope.BOLT),
                java.net.InetAddress.getByName("::1"),
                "::1",
                false);

        assertTrue(handshake.serverSubject().contains("CN=::1"), handshake.serverSubject());
    }

    @Test
    @DisplayName("an IP not listed in the certificate is rejected")
    void anUnlistedAddressIsRejected(@TempDir Path directory) throws Exception {
        // The certificate covers 10.1.2.3 only, but the connection is to loopback, so hostname
        // verification must fail even though the chain itself is trusted.
        TestBundles.Run run = TestBundles.generate(
                directory, "--node", "n1:10.1.2.3", "--scopes", "bolt");

        SSLContext server = TestBundles.sslContext(run.node("n1"), Scope.BOLT);
        SSLContext client = TestBundles.trustOnlyContext(run.node("n1"), Scope.BOLT);

        assertThrows(
                Exception.class,
                () -> TestBundles.handshake(
                        server,
                        client,
                        java.net.InetAddress.getLoopbackAddress().getHostAddress(),
                        false));
    }

    private static boolean hasIpv6Loopback() {
        try {
            var loopback = java.net.NetworkInterface.getByName("lo0");
            if (loopback == null) {
                loopback = java.net.NetworkInterface.getByName("lo");
            }
            return loopback != null
                    && loopback.inetAddresses().anyMatch(a -> a instanceof java.net.Inet6Address);
        } catch (java.net.SocketException e) {
            return false;
        }
    }

    @Test
    @DisplayName("a name absent from the subjectAlternativeName is rejected")
    void anUnlistedHostnameIsRejected(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        SSLContext server = TestBundles.sslContext(run.node("core1"), Scope.BOLT);
        SSLContext client = TestBundles.trustOnlyContext(run.node("core1"), Scope.BOLT);

        // core1's certificate does not cover core9, which is what stops one member's material
        // being reused for another host.
        Exception failure = assertThrows(
                Exception.class,
                () -> TestBundles.handshake(server, client, "core9.example.com", false));
        assertTrue(
                describes(failure, "No subject alternative DNS name")
                        || describes(failure, "doesn't match")
                        || describes(failure, "No name matching"),
                "unexpected failure: " + failure);
    }

    @Test
    @DisplayName("a certificate from a different CA is rejected")
    void aForeignCertificateIsRejected(@TempDir Path directory) throws Exception {
        // Two independent runs mean two independent CAs, which is what an attacker presenting
        // their own certificate amounts to.
        Path ours = java.nio.file.Files.createDirectory(directory.resolve("ours"));
        Path theirs = java.nio.file.Files.createDirectory(directory.resolve("theirs"));
        TestBundles.Run trusted = TestBundles.twoNodeCluster(ours, "ca");
        TestBundles.Run foreign = TestBundles.twoNodeCluster(theirs, "ca");

        SSLContext impostor = TestBundles.sslContext(foreign.node("core1"), Scope.BOLT);
        SSLContext client = TestBundles.trustOnlyContext(trusted.node("core1"), Scope.BOLT);

        Exception failure = assertThrows(
                Exception.class,
                () -> TestBundles.handshake(impostor, client, "core1.example.com", false));
        assertTrue(
                describes(failure, "unable to find valid certification path")
                        || describes(failure, "PKIX path"),
                "unexpected failure: " + failure);
    }

    @Test
    @DisplayName("a client from a different CA cannot authenticate to the cluster")
    void aForeignClientCannotJoinTheCluster(@TempDir Path directory) throws Exception {
        Path ours = java.nio.file.Files.createDirectory(directory.resolve("ours"));
        Path theirs = java.nio.file.Files.createDirectory(directory.resolve("theirs"));
        TestBundles.Run cluster = TestBundles.twoNodeCluster(ours, "ca");
        TestBundles.Run outsider = TestBundles.twoNodeCluster(theirs, "ca");

        SSLContext server = TestBundles.sslContext(cluster.node("core1"), Scope.CLUSTER);
        SSLContext intruder = TestBundles.sslContext(outsider.node("core1"), Scope.CLUSTER);

        assertThrows(
                Exception.class,
                () -> TestBundles.handshake(server, intruder, "core1.example.com", true),
                "a certificate from an unknown CA must not satisfy client_auth=REQUIRE");
    }

    @Test
    @DisplayName("intermediate mode: the chain sent by the server validates against the root")
    void intermediateChainValidates(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "intermediate");

        // The client trusts only the root; the intermediate has to arrive in the handshake, which
        // is why it is written into public.crt rather than into trusted/.
        assertEquals(List.of("root-ca.crt"), TestBundles.trustedFileNames(run.node("core1"), Scope.CLUSTER));
        assertEquals(
                2,
                TestBundles.certificates(
                                com.neo4j.tools.certtool.output.Layout.publicCertificate(
                                        run.node("core1"), Scope.CLUSTER))
                        .size());

        TestBundles.Handshake handshake = TestBundles.handshake(
                TestBundles.sslContext(run.node("core1"), Scope.CLUSTER),
                TestBundles.sslContext(run.node("core2"), Scope.CLUSTER),
                "core1.example.com",
                true);

        assertTrue(handshake.serverSubject().contains("CN=core1.example.com"));
        assertTrue(handshake.clientSubject().contains("CN=core2.example.com"));
    }

    @Test
    @DisplayName("self-signed mode: cross-trusted members authenticate each other")
    void selfSignedMembersTrustEachOther(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "self-signed");

        TestBundles.Handshake handshake = TestBundles.handshake(
                TestBundles.sslContext(run.node("core1"), Scope.CLUSTER),
                TestBundles.sslContext(run.node("core2"), Scope.CLUSTER),
                "core1.example.com",
                true);

        assertTrue(handshake.serverSubject().contains("CN=core1.example.com"));
        assertTrue(handshake.clientSubject().contains("CN=core2.example.com"));
    }

    @Test
    @DisplayName("RSA keys work end to end as well")
    void rsaKeysAlsoHandshake(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca", "--key-type", "rsa-3072");

        TestBundles.Handshake handshake = TestBundles.handshake(
                TestBundles.sslContext(run.node("core1"), Scope.CLUSTER),
                TestBundles.sslContext(run.node("core2"), Scope.CLUSTER),
                "core1.example.com",
                true);

        assertTrue(handshake.serverSubject().contains("CN=core1.example.com"));
    }

    @Test
    @DisplayName("P-384 keys work end to end as well")
    void p384KeysAlsoHandshake(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca", "--key-type", "ec-p384");

        TestBundles.Handshake handshake = TestBundles.handshake(
                TestBundles.sslContext(run.node("core1"), Scope.CLUSTER),
                TestBundles.sslContext(run.node("core2"), Scope.CLUSTER),
                "core1.example.com",
                true);

        assertTrue(handshake.serverSubject().contains("CN=core1.example.com"));
    }

    @Test
    @DisplayName("TLS 1.3 is available, so the CBC suites Neo4j dropped in 2025.01 are not needed")
    void tls13IsNegotiated(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        TestBundles.Handshake handshake = TestBundles.handshake(
                TestBundles.sslContext(run.node("core1"), Scope.BOLT),
                TestBundles.trustOnlyContext(run.node("core1"), Scope.BOLT),
                "core1.example.com",
                false);

        assertEquals("TLSv1.3", handshake.protocol());
        assertTrue(
                !handshake.cipherSuite().contains("_CBC_"),
                "negotiated a CBC suite: " + handshake.cipherSuite());
    }

    /** Whether a failure, or anything it wraps, mentions the given text. */
    private static boolean describes(Throwable failure, String text) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause.getMessage() != null && cause.getMessage().contains(text)) {
                return true;
            }
            if (cause.getCause() == cause) {
                break;
            }
        }
        return false;
    }
}
