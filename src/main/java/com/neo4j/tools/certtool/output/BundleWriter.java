package com.neo4j.tools.certtool.output;

import com.neo4j.tools.certtool.CertificateGenerator.Authority;
import com.neo4j.tools.certtool.CertificateGenerator.NodeBundle;
import com.neo4j.tools.certtool.CertificateGenerator.Result;
import com.neo4j.tools.certtool.CertificateGenerator.ScopeMaterial;
import com.neo4j.tools.certtool.CertificateGenerator.TrustAnchor;
import com.neo4j.tools.certtool.Options;
import com.neo4j.tools.certtool.PasswordProvider;
import com.neo4j.tools.certtool.crypto.Pem;
import com.neo4j.tools.certtool.crypto.Pkcs8;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Writes generated material to disk with the permissions Neo4j expects.
 *
 * <p>Per-node bundles are staged under the output directory, which is itself mode {@code 0700}:
 * the encrypted private keys of every node sit there until they are distributed, so the staging
 * area is more sensitive than any single node's live directory.
 */
public final class BundleWriter {

    private final Options options;
    private final PasswordProvider passwords;
    private final SecureRandom random;
    private final Instant now;
    private final Reporter reporter;

    public BundleWriter(
            Options options,
            PasswordProvider passwords,
            SecureRandom random,
            Instant now,
            Reporter reporter) {
        this.options = options;
        this.passwords = passwords;
        this.random = random;
        this.now = now;
        this.reporter = reporter;
    }

    /** Writes the CA material and every node bundle, then installs one node if asked to. */
    public void write(Result result) throws IOException, GeneralSecurityException {
        Path root = options.outputDirectory();
        requireUsableDirectory(root, "output directory");
        FilePermissions.createDirectories(root, FilePermissions.PRIVATE_DIRECTORY);

        writeAuthorities(root, result);

        for (NodeBundle bundle : result.nodes()) {
            writeNodeBundle(root.resolve(bundle.node().name()), bundle);
        }

        if (options.installNode().isPresent()) {
            String nodeName = options.installNode().get();
            NodeBundle bundle = result.nodes().stream()
                    .filter(candidate -> candidate.node().name().equals(nodeName))
                    .findFirst()
                    .orElseThrow(() -> new IOException("No generated bundle for node " + nodeName));
            install(bundle);
        }
    }

    // --- Certificate authority -------------------------------------------------------------

    private void writeAuthorities(Path root, Result result)
            throws IOException, GeneralSecurityException {
        if (result.authorities().stream().noneMatch(Authority::newlyCreated)) {
            return;
        }
        Path caDirectory = root.resolve(Layout.CA_DIRECTORY);
        FilePermissions.createDirectories(caDirectory, FilePermissions.PRIVATE_DIRECTORY);

        // The list is ordered root first, so index 0 is always the root and index 1, when
        // present, is the intermediate that issues the leaves.
        List<Authority> authorities = result.authorities();
        for (int i = 0; i < authorities.size(); i++) {
            Authority authority = authorities.get(i);
            if (!authority.newlyCreated()) {
                continue;
            }
            boolean isRoot = i == 0;
            String certificateFile =
                    isRoot ? Layout.CA_CERTIFICATE_FILE : Layout.INTERMEDIATE_CERTIFICATE_FILE;
            String keyFile = isRoot ? Layout.CA_KEY_FILE : Layout.INTERMEDIATE_KEY_FILE;
            String subject = isRoot ? "ca" : "intermediate";

            FilePermissions.write(
                    caDirectory.resolve(certificateFile),
                    toPem(authority.certificate()),
                    FilePermissions.PUBLIC_READ);
            writeEncryptedKey(
                    caDirectory.resolve(keyFile), authority.privateKey(), passwords.forSubject(subject));

            reporter.info(
                    "  %-14s %s%n                 valid until %s",
                    authority.label(),
                    authority.subject(),
                    authority.certificate().getNotAfter().toInstant());
        }

        FilePermissions.write(
                caDirectory.resolve(Layout.CA_README_FILE),
                ConfSnippet.caReadme(),
                FilePermissions.OWNER_READ_ONLY);
        applyOwnership(caDirectory);
    }

    // --- Node bundles ----------------------------------------------------------------------

    private void writeNodeBundle(Path nodeRoot, NodeBundle bundle)
            throws IOException, GeneralSecurityException {
        FilePermissions.createDirectories(nodeRoot, FilePermissions.PRIVATE_DIRECTORY);
        char[] password = passwords.forSubject(bundle.node().name());

        writeCertificatesTree(nodeRoot, bundle, password);

        // The snippet carries the private key password, so it is as sensitive as the key itself,
        // and is streamed straight to disk rather than assembled in memory first.
        FilePermissions.writeWith(
                nodeRoot.resolve(Layout.CONF_SNIPPET_FILE),
                FilePermissions.OWNER_READ_ONLY,
                stream -> ConfSnippet.writeTo(stream, bundle, password, now));

        applyOwnership(nodeRoot);

        reporter.info(
                "  %-14s %s%n                 %s%n                 valid until %s",
                bundle.node().name(),
                String.join(", ", bundle.node().subjectAlternativeNames()),
                nodeRoot.resolve(Layout.CERTIFICATES_DIRECTORY),
                bundle.scopes().getFirst().certificate().getNotAfter().toInstant());
    }

    /**
     * Writes {@code certificates/<scope>/...} under {@code root}, which is either a staging bundle
     * or a live {@code NEO4J_HOME}.
     */
    private void writeCertificatesTree(Path root, NodeBundle bundle, char[] password)
            throws IOException, GeneralSecurityException {
        FilePermissions.createDirectories(
                Layout.certificates(root), FilePermissions.PUBLIC_DIRECTORY);

        for (ScopeMaterial material : bundle.scopes()) {
            Path scopeDirectory = Layout.scope(root, material.scope());
            FilePermissions.createDirectories(scopeDirectory, FilePermissions.PUBLIC_DIRECTORY);
            FilePermissions.createDirectories(
                    Layout.trusted(root, material.scope()), FilePermissions.PUBLIC_DIRECTORY);
            // Created empty: Neo4j reads certificate revocation lists from here, and the policy
            // fails to load if the directory is missing.
            FilePermissions.createDirectories(
                    Layout.revoked(root, material.scope()), FilePermissions.PUBLIC_DIRECTORY);

            writeEncryptedKey(
                    Layout.privateKey(root, material.scope()), material.privateKey(), password);

            StringBuilder chain = new StringBuilder();
            for (X509Certificate certificate : material.certificateChain()) {
                chain.append(toPem(certificate));
            }
            FilePermissions.write(
                    Layout.publicCertificate(root, material.scope()),
                    chain.toString(),
                    FilePermissions.PUBLIC_READ);

            for (TrustAnchor anchor : material.trustAnchors()) {
                FilePermissions.write(
                        Layout.trusted(root, material.scope()).resolve(anchor.fileName()),
                        toPem(anchor.certificate()),
                        FilePermissions.PUBLIC_READ);
            }
        }
    }

    private void writeEncryptedKey(Path file, PrivateKey privateKey, char[] password)
            throws IOException, GeneralSecurityException {
        byte[] encrypted =
                Pkcs8.encrypt(privateKey, password, options.pbkdf2Iterations(), random);
        FilePermissions.write(
                file,
                Pem.encode(Pem.LABEL_ENCRYPTED_PRIVATE_KEY, encrypted),
                FilePermissions.OWNER_READ_ONLY);
    }

    private static String toPem(X509Certificate certificate) throws CertificateEncodingException {
        return Pem.encode(Pem.LABEL_CERTIFICATE, certificate.getEncoded());
    }

    // --- Installing into a live NEO4J_HOME -------------------------------------------------

    private void install(NodeBundle bundle) throws IOException, GeneralSecurityException {
        Path neo4jHome = options.neo4jHome().orElseThrow();
        if (!Files.isDirectory(neo4jHome)) {
            throw new IOException("--neo4j-home is not a directory: " + neo4jHome);
        }
        Path certificates = Layout.certificates(neo4jHome);
        for (var material : bundle.scopes()) {
            requireUsableDirectory(
                    Layout.scope(neo4jHome, material.scope()),
                    "existing " + material.scope().directoryName() + " policy directory");
        }

        char[] password = passwords.forSubject(bundle.node().name());
        writeCertificatesTree(neo4jHome, bundle, password);
        applyOwnership(certificates);

        reporter.blankLine();
        reporter.info("Installed node '%s' into %s", bundle.node().name(), certificates);
        if (options.owner().isEmpty()) {
            reporter.info(
                    "  Set ownership to the Neo4j service user:  chown -R neo4j:neo4j %s",
                    certificates);
        }
        reporter.info(
                "  Merge %s into %s",
                options.outputDirectory()
                        .resolve(bundle.node().name())
                        .resolve(Layout.CONF_SNIPPET_FILE),
                neo4jHome.resolve("conf").resolve("neo4j.conf"));
    }

    // --- Shared helpers --------------------------------------------------------------------

    /**
     * Refuses to write into a directory that already has contents, unless {@code --force} was
     * given. Silently overwriting certificate material could break a running cluster.
     */
    private void requireUsableDirectory(Path directory, String description) throws IOException {
        if (!Files.exists(directory)) {
            return;
        }
        if (!Files.isDirectory(directory)) {
            throw new IOException("Not a directory: " + directory);
        }
        if (options.force()) {
            return;
        }
        try (DirectoryStream<Path> contents = Files.newDirectoryStream(directory)) {
            if (contents.iterator().hasNext()) {
                throw new IOException(
                        "The %s %s is not empty. Move it aside, choose another path, or pass --force to overwrite."
                                .formatted(description, directory));
            }
        }
    }

    /**
     * Applies {@code --owner user[:group]} to a tree, so that material written as root ends up
     * owned by the Neo4j service user.
     */
    private void applyOwnership(Path root) throws IOException {
        Optional<String> specification = options.owner();
        if (specification.isEmpty()) {
            return;
        }
        String[] parts = specification.get().split(":", 2);
        UserPrincipalLookupService lookup =
                root.getFileSystem().getUserPrincipalLookupService();

        UserPrincipal user;
        GroupPrincipal group = null;
        try {
            user = lookup.lookupPrincipalByName(parts[0]);
            if (parts.length == 2 && !parts[1].isBlank()) {
                group = lookup.lookupPrincipalByGroupName(parts[1]);
            }
        } catch (IOException e) {
            throw new IOException("--owner: " + e.getMessage(), e);
        }

        List<Path> paths = new ArrayList<>();
        try (var walk = Files.walk(root)) {
            walk.forEach(paths::add);
        }
        for (Path path : paths) {
            PosixFileAttributeView view =
                    Files.getFileAttributeView(path, PosixFileAttributeView.class);
            if (view == null) {
                throw new IOException(
                        "--owner is only supported on file systems with POSIX ownership");
            }
            try {
                // The tree was created by this run, but resolving through a symlink while changing
                // ownership would hand a file outside it to the Neo4j user.
                if (Files.isSymbolicLink(path)) {
                    continue;
                }
                view.setOwner(user);
                if (group != null) {
                    view.setGroup(group);
                }
            } catch (IOException e) {
                throw new IOException(
                        "Cannot change ownership of %s to %s: %s (run as root, or omit --owner and use chown afterwards)"
                                .formatted(path, specification.get(), e.getMessage()),
                        e);
            }
        }
    }
}
