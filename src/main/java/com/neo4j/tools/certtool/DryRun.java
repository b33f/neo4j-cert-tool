package com.neo4j.tools.certtool;

import com.neo4j.tools.certtool.model.NodeSpec;
import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.model.TrustMode;
import com.neo4j.tools.certtool.output.FilePermissions;
import com.neo4j.tools.certtool.output.Layout;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Works out what a generate run would do, without doing any of it.
 *
 * <p>The plan is derived from {@link Layout} and the {@link FilePermissions} constants — the same
 * sources the real writer uses — so the two cannot describe different filenames or modes. A test
 * compares the plan against the files an actual run produces, which is what keeps them honest as
 * the layout changes.
 *
 * <p>Nothing here generates keys or certificates. A dry run is meant to be immediate and free of
 * side effects, and every path and permission is decided by the options alone.
 */
public final class DryRun {

    /** A file or directory the run would create. */
    public record PlannedEntry(
            Path path, boolean directory, Set<PosixFilePermission> permissions, String note) {}

    /** Something that would stop the run before it wrote anything useful. */
    public record Blocker(String description, String remedy) {}

    /** The outcome of planning a run. */
    public record Plan(List<PlannedEntry> entries, List<Blocker> blockers) {

        public boolean wouldSucceed() {
            return blockers.isEmpty();
        }

        public long files() {
            return entries.stream().filter(entry -> !entry.directory()).count();
        }

        public long directories() {
            return entries.stream().filter(PlannedEntry::directory).count();
        }
    }

    private final Options options;
    private final List<PlannedEntry> entries = new ArrayList<>();
    private final List<Blocker> blockers = new ArrayList<>();

    public DryRun(Options options) {
        this.options = options;
    }

    public Plan plan() {
        planInputs();
        planStagingTree();
        options.neo4jHome().ifPresent(this::planInstallTree);
        return new Plan(List.copyOf(entries), List.copyOf(blockers));
    }

    // --- Inputs the run depends on ---------------------------------------------------------

    /** Checks that everything the run needs to read is present and usable. */
    private void planInputs() {
        if (options.passwordMode() == PasswordProvider.Mode.FILE) {
            Path file = options.passwordFile().orElseThrow();
            if (!Files.isReadable(file)) {
                blockers.add(new Blocker(
                        "the password file " + file + " does not exist or cannot be read",
                        "check the path, or use --generate-password"));
            } else {
                // Parsing it now turns a malformed file into a dry-run finding rather than a
                // failure part-way through a real run. Reading is side-effect free, and closing
                // immediately zeroes the passwords it read, which are not needed here.
                try {
                    PasswordProvider.fromFile(file, new java.security.SecureRandom()).close();
                } catch (IOException e) {
                    blockers.add(new Blocker("the password file " + file + " is not usable: "
                            + e.getMessage(), "correct the file's format"));
                }
            }
        }

        if (options.passwordMode() == PasswordProvider.Mode.PROMPT) {
            if (!PasswordProvider.terminalAvailable()) {
                blockers.add(new Blocker(
                        "passwords would be prompted for, but there is no terminal to prompt on",
                        "use --generate-password or --password-file when running unattended"));
            }
        }

        options.existingCaCertificate().ifPresent(certificate -> {
            if (!Files.isReadable(certificate)) {
                blockers.add(new Blocker(
                        "the CA certificate " + certificate + " does not exist or cannot be read",
                        "check the --ca-cert path"));
            }
        });
        options.existingCaKey().ifPresent(key -> {
            if (!Files.isReadable(key)) {
                blockers.add(new Blocker(
                        "the CA private key " + key + " does not exist or cannot be read",
                        "check the --ca-key path"));
            }
        });
        options.caPasswordFile().ifPresent(file -> {
            if (!Files.isReadable(file)) {
                blockers.add(new Blocker(
                        "the CA password file " + file + " does not exist or cannot be read",
                        "check the --ca-password-file path"));
            }
        });
    }

    // --- The staging tree ------------------------------------------------------------------

    private void planStagingTree() {
        Path root = options.outputDirectory();
        checkDestination(root, "output directory " + root);
        add(root, true, FilePermissions.PRIVATE_DIRECTORY, "holds every node's private key");

        if (options.trustMode().usesCa() && options.existingCaCertificate().isEmpty()) {
            Path ca = root.resolve(Layout.CA_DIRECTORY);
            add(ca, true, FilePermissions.PRIVATE_DIRECTORY, null);
            add(ca.resolve(Layout.CA_CERTIFICATE_FILE), false, FilePermissions.PUBLIC_READ, "root CA certificate");
            add(ca.resolve(Layout.CA_KEY_FILE), false, FilePermissions.OWNER_READ_ONLY, "root CA private key, encrypted");
            if (options.trustMode() == TrustMode.INTERMEDIATE) {
                add(ca.resolve(Layout.INTERMEDIATE_CERTIFICATE_FILE), false, FilePermissions.PUBLIC_READ, null);
                add(ca.resolve(Layout.INTERMEDIATE_KEY_FILE), false, FilePermissions.OWNER_READ_ONLY, "encrypted");
            }
            add(ca.resolve(Layout.CA_README_FILE), false, FilePermissions.OWNER_READ_ONLY, null);
        }

        for (NodeSpec node : options.nodes()) {
            Path nodeRoot = root.resolve(node.name());
            add(nodeRoot, true, FilePermissions.PRIVATE_DIRECTORY, null);
            planCertificatesTree(nodeRoot);
            add(
                    nodeRoot.resolve(Layout.CONF_SNIPPET_FILE),
                    false,
                    FilePermissions.OWNER_READ_ONLY,
                    "settings to merge, contains the key password");
        }
    }

    /** The install destination, which is a live installation rather than a staging area. */
    private void planInstallTree(Path neo4jHome) {
        if (options.installNode().isEmpty()) {
            return;
        }
        if (!Files.isDirectory(neo4jHome)) {
            blockers.add(new Blocker(
                    "--neo4j-home " + neo4jHome + " is not a directory",
                    "point it at an existing Neo4j installation"));
            return;
        }
        for (Scope scope : orderedScopes()) {
            checkDestination(
                    Layout.scope(neo4jHome, scope),
                    "existing " + scope.directoryName() + " policy directory in " + neo4jHome);
        }
        planCertificatesTree(neo4jHome);
    }

    /** {@code certificates/<scope>/...} under a bundle root or a live installation. */
    private void planCertificatesTree(Path root) {
        add(Layout.certificates(root), true, FilePermissions.PUBLIC_DIRECTORY, null);
        for (Scope scope : orderedScopes()) {
            add(Layout.scope(root, scope), true, FilePermissions.PUBLIC_DIRECTORY, scope.purpose());
            add(Layout.privateKey(root, scope), false, FilePermissions.OWNER_READ_ONLY, "encrypted private key");
            add(
                    Layout.publicCertificate(root, scope),
                    false,
                    FilePermissions.PUBLIC_READ,
                    options.trustMode() == TrustMode.INTERMEDIATE ? "leaf + intermediate" : null);
            add(Layout.trusted(root, scope), true, FilePermissions.PUBLIC_DIRECTORY, null);
            for (String anchor : trustAnchorFileNames()) {
                add(Layout.trusted(root, scope).resolve(anchor), false, FilePermissions.PUBLIC_READ, null);
            }
            add(Layout.revoked(root, scope), true, FilePermissions.PUBLIC_DIRECTORY, "empty, for CRLs");
        }
    }

    /**
     * The filenames that would appear in each {@code trusted/} directory, which depend on the trust
     * mode: a CA-backed run trusts one anchor, a self-signed run trusts every member.
     */
    private List<String> trustAnchorFileNames() {
        if (options.trustMode().usesCa()) {
            return List.of("root-ca.crt");
        }
        return options.nodes().stream().map(node -> node.name() + ".crt").sorted().toList();
    }

    // --- Shared helpers --------------------------------------------------------------------

    /** Flags a destination that already has contents, which only {@code --force} would overwrite. */
    private void checkDestination(Path directory, String description) {
        if (options.force() || !Files.exists(directory)) {
            return;
        }
        if (!Files.isDirectory(directory)) {
            blockers.add(new Blocker(description + " exists and is not a directory", "move it aside"));
            return;
        }
        try (DirectoryStream<Path> contents = Files.newDirectoryStream(directory)) {
            if (contents.iterator().hasNext()) {
                blockers.add(new Blocker(
                        "the " + description + " is not empty",
                        "move it aside, choose another path with --out, or pass --force to overwrite"));
            }
        } catch (IOException e) {
            blockers.add(new Blocker("cannot read " + directory + ": " + e.getMessage(), "check permissions"));
        }
    }

    private List<Scope> orderedScopes() {
        return java.util.Arrays.stream(Scope.values())
                .filter(scope -> options.scopes().contains(scope))
                .toList();
    }

    private void add(Path path, boolean directory, Set<PosixFilePermission> permissions, String note) {
        entries.add(new PlannedEntry(path, directory, permissions, note));
    }
}
