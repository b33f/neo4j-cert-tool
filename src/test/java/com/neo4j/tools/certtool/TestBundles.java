package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.neo4j.tools.certtool.crypto.PemFiles;
import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.output.FilePermissions;
import com.neo4j.tools.certtool.output.Layout;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Shared fixtures: runs the tool the way a user would, then loads the material it wrote back into
 * the JDK's TLS stack.
 *
 * <p>Tests deliberately go through {@link Main#run} and read the resulting files, rather than
 * calling the generator and inspecting objects in memory. That way encoding, permission and
 * layout mistakes are caught alongside logic mistakes.
 */
final class TestBundles {

    /** Password used for every generated key in the tests. */
    static final String PASSWORD = "test-password-not-a-secret";

    /**
     * PBKDF2 iterations for tests. The production default is deliberately expensive; a test suite
     * that generated dozens of keys at that cost would take minutes.
     */
    static final String TEST_ITERATIONS = "10000";

    /** How long a handshake may take before the test gives up. */
    private static final int HANDSHAKE_TIMEOUT_SECONDS = 30;

    private TestBundles() {}

    /** The output of one tool invocation. */
    record Run(int exitCode, Path outputDirectory, String stdout, String stderr) {

        Path node(String name) {
            return outputDirectory.resolve(name);
        }

        Path caDirectory() {
            return outputDirectory.resolve(Layout.CA_DIRECTORY);
        }

        String output() {
            return stdout + stderr;
        }
    }

    /**
     * Runs the tool with a password file and an output directory inside {@code workDirectory}.
     *
     * @param extraArguments arguments appended after the defaults, so they can override them
     */
    static Run run(Path workDirectory, String... extraArguments) throws IOException {
        Path passwordFile = passwordFile(workDirectory);
        Path output = workDirectory.resolve("out");

        List<String> arguments = new ArrayList<>(List.of(
                "--out", output.toString(),
                "--password-file", passwordFile.toString(),
                "--pbkdf2-iterations", TEST_ITERATIONS));
        arguments.addAll(List.of(extraArguments));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exitCode;
        try (PrintStream outStream = new PrintStream(out, true, StandardCharsets.UTF_8);
                PrintStream errStream = new PrintStream(err, true, StandardCharsets.UTF_8)) {
            exitCode = new Main(outStream, errStream).run(arguments.toArray(String[]::new));
        }
        return new Run(
                exitCode,
                output,
                out.toString(StandardCharsets.UTF_8),
                err.toString(StandardCharsets.UTF_8));
    }

    /** Runs the tool and asserts that it succeeded. */
    static Run generate(Path workDirectory, String... extraArguments) throws IOException {
        Run run = run(workDirectory, extraArguments);
        assertEquals(Main.EXIT_OK, run.exitCode(), "generation failed:\n" + run.output());
        return run;
    }

    /** A two-node cluster with the given trust mode, which most tests need. */
    static Run twoNodeCluster(Path workDirectory, String mode, String... extraArguments)
            throws IOException {
        List<String> arguments = new ArrayList<>(List.of(
                "--mode", mode,
                "--node", "core1:core1.example.com,localhost,127.0.0.1",
                "--node", "core2:core2.example.com,localhost,127.0.0.1"));
        arguments.addAll(List.of(extraArguments));
        return generate(workDirectory, arguments.toArray(String[]::new));
    }

    /** Writes the shared password file, readable only by its owner. */
    static Path passwordFile(Path workDirectory) throws IOException {
        Path file = workDirectory.resolve("passwords.txt");
        Files.writeString(file, PASSWORD + "\n", StandardCharsets.UTF_8);
        if (FilePermissions.posixSupported()) {
            Files.setPosixFilePermissions(file, FilePermissions.OWNER_READ_WRITE);
        }
        return file;
    }

    // --- Loading generated material into the JDK's TLS stack --------------------------------

    /**
     * Builds an {@link SSLContext} from a generated bundle exactly as a TLS server would: the
     * encrypted private key and certificate chain become the key material, and the {@code trusted/}
     * directory becomes the trust store.
     */
    static SSLContext sslContext(Path bundleRoot, Scope scope) throws Exception {
        char[] password = PASSWORD.toCharArray();
        List<X509Certificate> chain =
                PemFiles.readCertificates(Layout.publicCertificate(bundleRoot, scope));
        PrivateKey privateKey =
                PemFiles.readPrivateKey(Layout.privateKey(bundleRoot, scope), password);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("node", privateKey, password, chain.toArray(Certificate[]::new));
        KeyManagerFactory keyManagers =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, password);

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(
                keyManagers.getKeyManagers(),
                trustManagers(Layout.trusted(bundleRoot, scope)).getTrustManagers(),
                new SecureRandom());
        return context;
    }

    /** A context that trusts a bundle's {@code trusted/} directory but presents no certificate. */
    static SSLContext trustOnlyContext(Path bundleRoot, Scope scope) throws Exception {
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(
                null, trustManagers(Layout.trusted(bundleRoot, scope)).getTrustManagers(), new SecureRandom());
        return context;
    }

    private static TrustManagerFactory trustManagers(Path trustedDirectory) throws Exception {
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        int index = 0;
        List<Path> files;
        try (Stream<Path> children = Files.list(trustedDirectory)) {
            files = children.filter(Files::isRegularFile).sorted().toList();
        }
        for (Path file : files) {
            for (X509Certificate certificate : PemFiles.readCertificates(file)) {
                trustStore.setCertificateEntry("anchor-" + index++, certificate);
            }
        }
        TrustManagerFactory factory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trustStore);
        return factory;
    }

    /** What each side of a completed handshake saw. */
    record Handshake(String serverSubject, String clientSubject, String protocol, String cipherSuite) {}

    /**
     * Completes a real TLS handshake over the loopback interface and exchanges a byte in each
     * direction.
     *
     * <p>The client wraps a plain socket that is already connected to loopback, which lets the
     * hostname used for certificate verification be chosen independently of DNS. That is what makes
     * it possible to check that {@code core1.example.com} matches the certificate's
     * subjectAlternativeName without resolving the name.
     *
     * @param clientSideHostname the name the client believes it is connecting to
     * @param requireClientCertificate whether the server demands client authentication, as the
     *     cluster and backup scopes do
     */
    static Handshake handshake(
            SSLContext serverContext,
            SSLContext clientContext,
            String clientSideHostname,
            boolean requireClientCertificate)
            throws Exception {
        return handshake(
                serverContext,
                clientContext,
                InetAddress.getLoopbackAddress(),
                clientSideHostname,
                requireClientCertificate);
    }

    /**
     * As {@link #handshake}, with an explicit bind address so an IPv6-only certificate can be
     * exercised against {@code ::1}.
     */
    static Handshake handshake(
            SSLContext serverContext,
            SSLContext clientContext,
            InetAddress bindAddress,
            String clientSideHostname,
            boolean requireClientCertificate)
            throws Exception {
        try (SSLServerSocket serverSocket =
                        (SSLServerSocket) serverContext.getServerSocketFactory()
                                .createServerSocket(0, 1, bindAddress);
                ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {

            serverSocket.setNeedClientAuth(requireClientCertificate);
            int port = serverSocket.getLocalPort();

            Future<String[]> serverSide = executor.submit(() -> {
                try (SSLSocket socket = (SSLSocket) serverSocket.accept()) {
                    socket.setSoTimeout(HANDSHAKE_TIMEOUT_SECONDS * 1000);
                    socket.startHandshake();
                    socket.getOutputStream().write('S');
                    socket.getOutputStream().flush();
                    int received = socket.getInputStream().read();
                    if (received != 'C') {
                        throw new IllegalStateException("server read " + received + ", expected 'C'");
                    }
                    String clientSubject = requireClientCertificate
                            ? socket.getSession().getPeerPrincipal().getName()
                            : "";
                    return new String[] {clientSubject};
                }
            });

            String serverSubject;
            String protocol;
            String cipherSuite;
            try (Socket plain = new Socket(bindAddress, port);
                    SSLSocket socket = (SSLSocket) clientContext.getSocketFactory()
                            .createSocket(plain, clientSideHostname, port, true)) {
                socket.setSoTimeout(HANDSHAKE_TIMEOUT_SECONDS * 1000);
                SSLParameters parameters = socket.getSSLParameters();
                // Without this the JDK checks the chain but not whether the certificate belongs to
                // the host being contacted, which is the check Neo4j's verify_hostname enables.
                parameters.setEndpointIdentificationAlgorithm("HTTPS");
                socket.setSSLParameters(parameters);

                socket.startHandshake();
                int received = socket.getInputStream().read();
                if (received != 'S') {
                    throw new IllegalStateException("client read " + received + ", expected 'S'");
                }
                socket.getOutputStream().write('C');
                socket.getOutputStream().flush();

                serverSubject = socket.getSession().getPeerPrincipal().getName();
                protocol = socket.getSession().getProtocol();
                cipherSuite = socket.getSession().getCipherSuite();
            }

            // Only now that the client socket is closed, and its close_notify sent. The server's
            // own close() drains input waiting for that alert, so waiting on the server here while
            // the client socket is still open would deadlock the two sides against each other.
            String[] fromServer = serverSide.get(HANDSHAKE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            return new Handshake(serverSubject, fromServer[0], protocol, cipherSuite);
        }
    }

    /** Reads a generated PEM file's certificates. */
    static List<X509Certificate> certificates(Path file) throws Exception {
        return PemFiles.readCertificates(file);
    }

    /** Lists the files in a {@code trusted/} directory, sorted by name. */
    static List<String> trustedFileNames(Path bundleRoot, Scope scope) throws IOException {
        try (Stream<Path> children = Files.list(Layout.trusted(bundleRoot, scope))) {
            return children.map(path -> path.getFileName().toString()).sorted().toList();
        }
    }
}
