package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.output.FilePermissions;
import com.neo4j.tools.certtool.output.Layout;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exercises the tool the way a user does: whole invocations, checked by their exit code and output. */
class EndToEndTest {

    private static Run invoke(String... arguments) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exitCode;
        try (PrintStream outStream = new PrintStream(out, true, StandardCharsets.UTF_8);
                PrintStream errStream = new PrintStream(err, true, StandardCharsets.UTF_8)) {
            exitCode = new Main(outStream, errStream).run(arguments);
        }
        return new Run(
                exitCode,
                out.toString(StandardCharsets.UTF_8),
                err.toString(StandardCharsets.UTF_8));
    }

    private record Run(int exitCode, String stdout, String stderr) {
        String all() {
            return stdout + stderr;
        }
    }

    @Test
    @DisplayName("help explains how to choose a trust mode")
    void helpGuidesTheTrustModeChoice() {
        Run run = invoke("help");

        assertEquals(Main.EXIT_OK, run.exitCode());
        assertTrue(run.stdout().contains("CHOOSING A TRUST MODE"));
        assertTrue(run.stdout().contains("If you are unsure, use the default."));
        // Each mode has to say when it is the right choice, not just what it does.
        assertTrue(run.stdout().contains("Use this for almost every cluster"));
        assertTrue(run.stdout().contains("Use this only for a single-instance database"));
        assertTrue(run.stdout().contains("if the root key must stay offline permanently"));
        // And the security caveat has to be stated where users will see it.
        assertTrue(run.stdout().contains("Neo4j reads private_key_password from neo4j.conf in clear"));
    }

    @Test
    @DisplayName("version reports the tool and the JVM it is running on")
    void versionReportsTheRuntime() {
        Run run = invoke("version");

        assertEquals(Main.EXIT_OK, run.exitCode());
        assertTrue(run.stdout().contains("neo4j-cert-tool"));
        assertTrue(run.stdout().contains("Running on Java"));
    }

    @Test
    @DisplayName("bad usage exits with code 2 and points at help")
    void badUsageIsDistinguishableFromFailure() {
        Run run = invoke("--node");

        assertEquals(Main.EXIT_USAGE, run.exitCode());
        assertTrue(run.stderr().contains("help"), run.stderr());
    }

    @Test
    @DisplayName("a run with no nodes explains what to pass")
    void missingNodesAreExplained() {
        Run run = invoke();

        assertEquals(Main.EXIT_USAGE, run.exitCode());
        assertTrue(run.stderr().contains("--node core1:core1.example.com"), run.stderr());
    }

    @Test
    @DisplayName("generation self-verifies and reports its checks")
    void generationSelfVerifies(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        assertTrue(run.stdout().contains("Verifying what was written"), run.output());
        assertTrue(run.stdout().contains("checks passed"), run.output());
        assertTrue(run.stdout().contains("Next steps"), run.output());
    }

    @Test
    @DisplayName("the verify command passes on freshly generated material")
    void verifyPassesOnGeneratedMaterial(@TempDir Path directory) throws Exception {
        TestBundles.Run generated = TestBundles.twoNodeCluster(directory, "ca");

        Run verified = invoke(
                "verify",
                "--out", generated.outputDirectory().toString(),
                "--password-file", TestBundles.passwordFile(directory).toString());

        assertEquals(Main.EXIT_OK, verified.exitCode(), verified.all());
        assertTrue(verified.stdout().contains("All"), verified.stdout());
        assertTrue(verified.stdout().contains("checks passed"), verified.stdout());
    }

    @Test
    @DisplayName("verify fails when a certificate has been swapped for another CA's")
    void verifyDetectsAnUntrustedCertificate(@TempDir Path directory) throws Exception {
        Path ours = Files.createDirectory(directory.resolve("ours"));
        Path theirs = Files.createDirectory(directory.resolve("theirs"));
        TestBundles.Run mine = TestBundles.twoNodeCluster(ours, "ca");
        TestBundles.Run other = TestBundles.twoNodeCluster(theirs, "ca");

        // Replace one certificate with one from a different CA, leaving trusted/ untouched.
        Files.copy(
                Layout.publicCertificate(other.node("core1"), Scope.BOLT),
                Layout.publicCertificate(mine.node("core1"), Scope.BOLT),
                java.nio.file.StandardCopyOption.REPLACE_EXISTING);

        Run verified = invoke(
                "verify",
                "--out", mine.outputDirectory().toString(),
                "--password-file", TestBundles.passwordFile(ours).toString());

        assertEquals(Main.EXIT_FAILURE, verified.exitCode());
        assertTrue(
                verified.stderr().contains("private key does not match")
                        || verified.stderr().contains("chain does not validate"),
                verified.stderr());
    }

    @Test
    @DisplayName("verify fails when trusted/ has been emptied")
    void verifyDetectsAnEmptyTrustStore(@TempDir Path directory) throws Exception {
        TestBundles.Run generated = TestBundles.twoNodeCluster(directory, "ca");
        Files.delete(Layout.trusted(generated.node("core1"), Scope.CLUSTER).resolve("root-ca.crt"));

        Run verified = invoke(
                "verify",
                "--out", generated.outputDirectory().toString(),
                "--password-file", TestBundles.passwordFile(directory).toString());

        assertEquals(Main.EXIT_FAILURE, verified.exitCode());
        assertTrue(verified.stderr().contains("holds no certificates"), verified.stderr());
    }

    @Test
    @DisplayName("verify fails when a private key has been made group readable")
    void verifyDetectsLoosePermissions(@TempDir Path directory) throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(FilePermissions.posixSupported());
        TestBundles.Run generated = TestBundles.twoNodeCluster(directory, "ca");

        Path key = Layout.privateKey(generated.node("core1"), Scope.BOLT);
        Files.setPosixFilePermissions(
                key, java.nio.file.attribute.PosixFilePermissions.fromString("rw-r--r--"));

        Run verified = invoke(
                "verify",
                "--out", generated.outputDirectory().toString(),
                "--password-file", TestBundles.passwordFile(directory).toString());

        assertEquals(Main.EXIT_FAILURE, verified.exitCode());
        assertTrue(verified.stderr().contains("must not be readable beyond its owner"), verified.stderr());
    }

    @Test
    @DisplayName("verify fails with the wrong password")
    void verifyDetectsTheWrongPassword(@TempDir Path directory) throws Exception {
        TestBundles.Run generated = TestBundles.twoNodeCluster(directory, "ca");

        Path wrong = directory.resolve("wrong.txt");
        Files.writeString(wrong, "definitely-not-the-password\n");

        Run verified = invoke(
                "verify",
                "--out", generated.outputDirectory().toString(),
                "--password-file", wrong.toString());

        assertEquals(Main.EXIT_FAILURE, verified.exitCode());
        assertTrue(verified.stderr().contains("password appears to be wrong"), verified.stderr());
    }

    @Test
    @DisplayName("verify works against an installed NEO4J_HOME too")
    void verifyAcceptsASingleBundle(@TempDir Path directory) throws Exception {
        TestBundles.Run generated = TestBundles.twoNodeCluster(directory, "ca");

        Run verified = invoke(
                "verify",
                "--out", generated.node("core1").toString(),
                "--password-file", TestBundles.passwordFile(directory).toString());

        assertEquals(Main.EXIT_OK, verified.exitCode(), verified.all());
    }

    @Test
    @DisplayName("verify reports a path with no certificates at all")
    void verifyReportsAnEmptyDirectory(@TempDir Path directory) throws Exception {
        Path empty = Files.createDirectory(directory.resolve("empty"));

        Run verified = invoke(
                "verify",
                "--out", empty.toString(),
                "--password-file", TestBundles.passwordFile(directory).toString());

        assertEquals(Main.EXIT_FAILURE, verified.exitCode());
        assertTrue(verified.stderr().contains("no certificates/ directory"), verified.stderr());
    }

    @Test
    @DisplayName("a non-empty output directory is refused unless forced")
    void existingOutputIsProtected(@TempDir Path directory) throws Exception {
        TestBundles.twoNodeCluster(directory, "ca");

        TestBundles.Run second = TestBundles.run(
                directory, "--mode", "ca", "--node", "core1:core1.example.com");

        assertEquals(Main.EXIT_FAILURE, second.exitCode());
        assertTrue(second.stderr().contains("--force"), second.stderr());
    }

    @Test
    @DisplayName("--force replaces an existing output directory")
    void forceOverwrites(@TempDir Path directory) throws Exception {
        TestBundles.Run first = TestBundles.twoNodeCluster(directory, "ca");
        String originalSerial = TestBundles.certificates(
                        Layout.publicCertificate(first.node("core1"), Scope.BOLT))
                .getFirst()
                .getSerialNumber()
                .toString();

        TestBundles.Run second = TestBundles.twoNodeCluster(directory, "ca", "--force");
        String newSerial = TestBundles.certificates(
                        Layout.publicCertificate(second.node("core1"), Scope.BOLT))
                .getFirst()
                .getSerialNumber()
                .toString();

        assertNotEquals(originalSerial, newSerial);
    }

    @Test
    @DisplayName("generated passwords are reported once and reach the conf snippet")
    void generatedPasswordsAreReported(@TempDir Path directory) throws Exception {
        Run run = invoke(
                "--out", directory.resolve("out").toString(),
                "--pbkdf2-iterations", TestBundles.TEST_ITERATIONS,
                "--node", "core1:core1.example.com",
                "--generate-password");

        assertEquals(Main.EXIT_OK, run.exitCode(), run.all());
        assertTrue(run.stdout().contains("Generated private key passwords"), run.stdout());

        // Pull the reported password out of the summary and confirm it is what the snippet holds.
        // Only the lines after the header are passwords; earlier lines list the node's names.
        List<String> lines = run.stdout().lines().toList();
        int header = lines.indexOf(
                "Generated private key passwords — record these now, they are not recoverable:");
        assertTrue(header >= 0, run.stdout());
        String password = lines.subList(header + 1, lines.size()).stream()
                .filter(line -> line.strip().startsWith("core1 "))
                .map(line -> line.strip().substring("core1".length()).strip())
                .findFirst()
                .orElseThrow();
        assertTrue(password.length() >= 32, "a generated password should be long: " + password.length());

        String snippet = Files.readString(
                directory.resolve("out").resolve("core1").resolve(Layout.CONF_SNIPPET_FILE));
        assertTrue(snippet.contains("private_key_password=" + password), snippet);
    }

    @Test
    @DisplayName("the conf snippet enables each scope with the right defaults")
    void theConfSnippetIsComplete(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        String snippet = Files.readString(run.node("core1").resolve(Layout.CONF_SNIPPET_FILE));

        for (Scope scope : Scope.values()) {
            String prefix = scope.configPrefix();
            assertTrue(snippet.contains(prefix + ".enabled=true"), prefix);
            assertTrue(snippet.contains(prefix + ".base_directory=certificates/" + scope.directoryName()));
            assertTrue(snippet.contains(prefix + ".private_key=private.key"));
            assertTrue(snippet.contains(prefix + ".public_certificate=public.crt"));
            assertTrue(snippet.contains(prefix + ".trusted_dir=trusted"));
            assertTrue(snippet.contains(prefix + ".revoked_dir=revoked"));
            assertTrue(snippet.contains(prefix + ".private_key_password="));
            if (scope.mutualAuthentication()) {
                assertTrue(snippet.contains(prefix + ".client_auth=REQUIRE"), prefix);
                assertTrue(snippet.contains(prefix + ".verify_hostname=true"), prefix);
            } else {
                assertTrue(snippet.contains(prefix + ".client_auth=NONE"), prefix);
            }
            // Negotiation parameters stay commented so merging cannot change a working cluster.
            assertTrue(snippet.contains("# " + prefix + ".tls_versions="), prefix);
        }
        assertTrue(snippet.contains("server.bolt.tls_level=REQUIRED"));
        assertTrue(snippet.contains("server.https.enabled=true"));
    }

    @Test
    @DisplayName("--install writes into a NEO4J_HOME and leaves the staging bundle intact")
    void installWritesIntoNeo4jHome(@TempDir Path directory) throws Exception {
        Path neo4jHome = Files.createDirectory(directory.resolve("neo4j"));
        Files.createDirectory(neo4jHome.resolve("conf"));

        TestBundles.Run run = TestBundles.twoNodeCluster(
                directory, "ca", "--install-node", "core1", "--neo4j-home", neo4jHome.toString());

        for (Scope scope : Scope.values()) {
            assertTrue(Files.isRegularFile(Layout.privateKey(neo4jHome, scope)), scope + " key");
            assertTrue(Files.isRegularFile(Layout.publicCertificate(neo4jHome, scope)), scope + " cert");
            assertTrue(Files.isDirectory(Layout.revoked(neo4jHome, scope)), scope + " revoked/");
        }
        assertTrue(run.stdout().contains("Installed node 'core1'"), run.output());
        assertTrue(run.stdout().contains("chown -R neo4j:neo4j"), run.output());
        assertTrue(Files.isRegularFile(Layout.privateKey(run.node("core1"), Scope.BOLT)));

        if (FilePermissions.posixSupported()) {
            assertEquals(
                    FilePermissions.OWNER_READ_ONLY,
                    FilePermissions.read(Layout.privateKey(neo4jHome, Scope.BOLT)));
        }

        // The installed material has to stand on its own.
        Run verified = invoke(
                "verify",
                "--out", neo4jHome.toString(),
                "--password-file", TestBundles.passwordFile(directory).toString());
        assertEquals(Main.EXIT_OK, verified.exitCode(), verified.all());
    }

    @Test
    @DisplayName("--install refuses to overwrite an existing policy directory")
    void installDoesNotClobberALiveInstallation(@TempDir Path directory) throws Exception {
        Path neo4jHome = Files.createDirectory(directory.resolve("neo4j"));
        Files.createDirectories(Layout.scope(neo4jHome, Scope.BOLT));
        Files.writeString(Layout.publicCertificate(neo4jHome, Scope.BOLT), "in use by a running cluster");

        TestBundles.Run run = TestBundles.run(
                directory,
                "--node", "core1:core1.example.com",
                "--install",
                "--neo4j-home", neo4jHome.toString());

        assertEquals(Main.EXIT_FAILURE, run.exitCode());
        assertTrue(run.stderr().contains("--force"), run.stderr());
        assertEquals(
                "in use by a running cluster",
                Files.readString(Layout.publicCertificate(neo4jHome, Scope.BOLT)));
    }

    @Test
    @DisplayName("a node can be added later by reusing the CA, without touching existing members")
    void aNodeCanBeAddedLater(@TempDir Path directory) throws Exception {
        TestBundles.Run original = TestBundles.twoNodeCluster(directory, "ca");
        Path caCertificate = original.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE);
        Path caKey = original.caDirectory().resolve(Layout.CA_KEY_FILE);

        Path laterDirectory = Files.createDirectory(directory.resolve("later"));
        TestBundles.Run added = TestBundles.generate(
                laterDirectory,
                "--node", "core3:core3.example.com,localhost,127.0.0.1",
                "--ca-cert", caCertificate.toString(),
                "--ca-key", caKey.toString(),
                "--ca-password-file", TestBundles.passwordFile(directory).toString());

        // The new node's trust anchor is byte-identical to what the existing members already hold,
        // which is what makes adding a node a no-op for them.
        assertEquals(
                Files.readString(Layout.trusted(original.node("core1"), Scope.CLUSTER).resolve("root-ca.crt")),
                Files.readString(Layout.trusted(added.node("core3"), Scope.CLUSTER).resolve("root-ca.crt")));
        assertFalse(Files.exists(added.caDirectory()), "an existing CA must not be written out again");

        // And the new node really can join: it authenticates against an original member.
        TestBundles.Handshake handshake = TestBundles.handshake(
                TestBundles.sslContext(original.node("core1"), Scope.CLUSTER),
                TestBundles.sslContext(added.node("core3"), Scope.CLUSTER),
                "core1.example.com",
                true);
        assertTrue(handshake.clientSubject().contains("CN=core3.example.com"));
    }

    @Test
    @DisplayName("reusing a CA whose pathLenConstraint forbids it is reported clearly")
    void aLeafOnlyCaCannotSignAnIntermediate(@TempDir Path directory) throws Exception {
        TestBundles.Run original = TestBundles.twoNodeCluster(directory, "ca");

        Path laterDirectory = Files.createDirectory(directory.resolve("later"));
        TestBundles.Run attempt = TestBundles.run(
                laterDirectory,
                "--mode", "intermediate",
                "--node", "core3:core3.example.com",
                "--ca-cert", original.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE).toString(),
                "--ca-key", original.caDirectory().resolve(Layout.CA_KEY_FILE).toString(),
                "--ca-password-file", TestBundles.passwordFile(directory).toString());

        assertEquals(Main.EXIT_FAILURE, attempt.exitCode());
        assertTrue(attempt.stderr().contains("pathLenConstraint=0"), attempt.stderr());
    }

    @Test
    @DisplayName("a mismatched CA certificate and key are caught")
    void aMismatchedCaIsCaught(@TempDir Path directory) throws Exception {
        Path first = Files.createDirectory(directory.resolve("first"));
        Path second = Files.createDirectory(directory.resolve("second"));
        TestBundles.Run one = TestBundles.twoNodeCluster(first, "ca");
        TestBundles.Run two = TestBundles.twoNodeCluster(second, "ca");

        Path third = Files.createDirectory(directory.resolve("third"));
        TestBundles.Run attempt = TestBundles.run(
                third,
                "--node", "core3:core3.example.com",
                "--ca-cert", one.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE).toString(),
                "--ca-key", two.caDirectory().resolve(Layout.CA_KEY_FILE).toString(),
                "--ca-password-file", TestBundles.passwordFile(first).toString());

        assertEquals(Main.EXIT_FAILURE, attempt.exitCode());
        assertTrue(attempt.stderr().contains("does not belong to the certificate"), attempt.stderr());
    }

    @Test
    @DisplayName("the CA directory carries instructions for keeping it safe")
    void theCaDirectoryExplainsItself(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        String readme = Files.readString(run.caDirectory().resolve(Layout.CA_README_FILE));

        assertTrue(readme.contains("Move it off this machine"));
        assertTrue(readme.contains("--ca-cert ca.crt --ca-key ca.key"));
    }

    @Test
    @DisplayName("--quiet prints nothing on success except generated secrets")
    void quietSuppressesTheSummary(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca", "--quiet");

        assertEquals(Main.EXIT_OK, run.exitCode());
        assertEquals("", run.stdout(), "nothing to say when there is nothing to report");
        assertEquals("", run.stderr());
    }

    @Test
    @DisplayName("a password file may give each node its own password")
    void perNodePasswordsAreSupported(@TempDir Path directory) throws Exception {
        Path passwords = directory.resolve("per-node.txt");
        Files.writeString(
                passwords,
                """
                # one password per node
                ca=ca-password-here
                core1=core1-password-here
                core2=core2-password-here
                """);

        Run run = invoke(
                "--out", directory.resolve("out").toString(),
                "--pbkdf2-iterations", TestBundles.TEST_ITERATIONS,
                "--node", "core1:core1.example.com",
                "--node", "core2:core2.example.com",
                "--password-file", passwords.toString());

        assertEquals(Main.EXIT_OK, run.exitCode(), run.all());

        // Each node's key must open with its own password and no other.
        var random = new java.security.SecureRandom();
        var core1Key = com.neo4j.tools.certtool.crypto.PemFiles.readPrivateKey(
                Layout.privateKey(directory.resolve("out").resolve("core1"), Scope.BOLT),
                "core1-password-here".toCharArray());
        assertTrue(core1Key != null);
        org.junit.jupiter.api.Assertions.assertThrows(
                java.security.GeneralSecurityException.class,
                () -> com.neo4j.tools.certtool.crypto.PemFiles.readPrivateKey(
                        Layout.privateKey(directory.resolve("out").resolve("core2"), Scope.BOLT),
                        "core1-password-here".toCharArray()));
    }

    @Test
    @DisplayName("a password file with conflicting formats is rejected")
    void ambiguousPasswordFilesAreRejected(@TempDir Path directory) throws Exception {
        Path passwords = directory.resolve("mixed.txt");
        Files.writeString(passwords, "a-bare-password\ncore1=another-password\n");

        Run run = invoke(
                "--out", directory.resolve("out").toString(),
                "--node", "core1:core1.example.com",
                "--password-file", passwords.toString());

        assertEquals(Main.EXIT_FAILURE, run.exitCode());
        assertTrue(run.stderr().contains("but not both"), run.stderr());
    }

    @Test
    @DisplayName("a config file drives a whole run")
    void aConfigFileDrivesTheRun(@TempDir Path directory) throws Exception {
        Path config = directory.resolve("cluster.properties");
        Files.writeString(
                config,
                """
                mode=ca
                key-type=ec-p256
                validity-days=100
                out=%s
                pbkdf2-iterations=%s
                node.core1=core1.example.com,10.0.0.11
                node.core2=core2.example.com,10.0.0.12
                node.core3=core3.example.com,10.0.0.13
                """
                        .formatted(directory.resolve("out"), TestBundles.TEST_ITERATIONS));

        Run run = invoke(
                "--config", config.toString(),
                "--password-file", TestBundles.passwordFile(directory).toString());

        assertEquals(Main.EXIT_OK, run.exitCode(), run.all());
        for (String node : List.of("core1", "core2", "core3")) {
            assertTrue(
                    Files.isRegularFile(
                            Layout.publicCertificate(directory.resolve("out").resolve(node), Scope.CLUSTER)),
                    node);
        }
    }
}
