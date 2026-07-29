package com.neo4j.tools.certtool;

import com.neo4j.tools.certtool.CertificateGenerator.Authority;
import com.neo4j.tools.certtool.CertificateGenerator.Result;
import com.neo4j.tools.certtool.crypto.DistinguishedName;
import com.neo4j.tools.certtool.crypto.PemFiles;
import com.neo4j.tools.certtool.model.TrustMode;
import com.neo4j.tools.certtool.output.BundleWriter;
import com.neo4j.tools.certtool.output.FilePermissions;
import com.neo4j.tools.certtool.output.Layout;
import com.neo4j.tools.certtool.output.Reporter;
import com.neo4j.tools.certtool.verify.BundleVerifier;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Command line entry point. */
public final class Main {

    /** Exit code for a successful run. */
    public static final int EXIT_OK = 0;

    /** Exit code for a run that failed for any reason other than bad arguments. */
    public static final int EXIT_FAILURE = 1;

    /** Exit code for arguments the user needs to correct. */
    public static final int EXIT_USAGE = 2;

    private final PrintStream out;
    private final PrintStream err;

    public Main(PrintStream out, PrintStream err) {
        this.out = out;
        this.err = err;
    }

    public static void main(String[] args) {
        System.exit(new Main(System.out, System.err).run(args));
    }

    /** Runs one invocation and returns the process exit code. */
    public int run(String[] args) {
        Options options;
        try {
            options = Cli.parse(args);
        } catch (Cli.UsageException e) {
            err.println(e.getMessage());
            err.println();
            err.println("Run 'neo4j-cert-tool help' for the full list of options.");
            return EXIT_USAGE;
        }

        Reporter reporter = new Reporter(out, err, options.quiet());
        try {
            return switch (options.command()) {
                case HELP -> {
                    out.print(Help.text());
                    yield EXIT_OK;
                }
                case VERSION -> {
                    out.println("neo4j-cert-tool " + version());
                    out.println(
                            "Running on Java "
                                    + System.getProperty("java.version")
                                    + " ("
                                    + System.getProperty("java.vendor")
                                    + ")");
                    yield EXIT_OK;
                }
                case GENERATE -> generate(options, reporter);
                case VERIFY -> verify(options, reporter);
            };
        } catch (IOException | GeneralSecurityException e) {
            err.println("Error: " + e.getMessage());
            return EXIT_FAILURE;
        } catch (IllegalStateException | IllegalArgumentException e) {
            // Password prompting and argument-derived values surface as these.
            err.println("Error: " + e.getMessage());
            return EXIT_FAILURE;
        }
    }

    // --- generate --------------------------------------------------------------------------

    private int generate(Options options, Reporter reporter)
            throws IOException, GeneralSecurityException {
        SecureRandom random = new SecureRandom();
        Instant now = Instant.now();

        reporter.info("neo4j-cert-tool %s", version());
        reporter.info("  trust mode     %s (%s)", options.trustMode().optionValue(), options.trustMode().summary());
        reporter.info("  key type       %s", options.keyType().describe());
        reporter.info(
                "  scopes         %s",
                options.scopes().stream()
                        .map(com.neo4j.tools.certtool.model.Scope::directoryName)
                        .sorted()
                        .reduce((a, b) -> a + ", " + b)
                        .orElse("none"));
        reporter.info("  leaf validity  %d days", options.validityDays());
        reporter.info("  passwords      %s", describePasswordSource(options));
        reporter.blankLine();

        if (options.dryRun()) {
            // Returns before any password is asked for and before anything is created.
            return report(new DryRun(options).plan(), options);
        }

        try (PasswordProvider passwords = createPasswordProvider(options, random)) {
            Optional<Authority> existingCa = loadExistingAuthority(options, passwords, random);

            Result result = new CertificateGenerator(options, random, now).generate(existingCa);

            reporter.info("Writing to %s", options.outputDirectory().toAbsolutePath());
            new BundleWriter(options, passwords, random, now, reporter).write(result);

            // Read everything back from disk and check it. A tool that produces certificates
            // should not report success until it has confirmed the files it wrote are usable.
            reporter.blankLine();
            reporter.info("Verifying what was written");
            BundleVerifier.Report report =
                    new BundleVerifier(passwords, random, now).verify(options.outputDirectory());
            for (BundleVerifier.Finding finding : report.problems()) {
                if (finding.severity() == BundleVerifier.Severity.ERROR) {
                    err.println("  " + finding);
                } else {
                    reporter.info("  " + finding);
                }
            }
            if (report.hasErrors()) {
                err.println();
                err.println(
                        "Error: the generated material did not pass verification. "
                                + "Nothing has been installed; do not distribute this output.");
                return EXIT_FAILURE;
            }
            reporter.info("  %d checks passed", report.checksRun());

            reportPasswords(passwords, reporter);
            reportNextSteps(options, result, reporter);
        }
        return EXIT_OK;
    }

    /** Prints the plan a dry run produced and returns the exit code for it. */
    private int report(DryRun.Plan plan, Options options) {
        out.println("DRY RUN — nothing will be written.");
        out.println();
        out.printf("Would create %d files and %d directories.%n", plan.files(), plan.directories());

        // Grouped under each destination with relative paths: absolute paths repeated on every
        // line would be unreadable and would wreck the column alignment.
        List<Path> roots = new java.util.ArrayList<>();
        roots.add(options.outputDirectory());
        if (options.installNode().isPresent()) {
            options.neo4jHome().ifPresent(roots::add);
        }
        // Longest first, so an entry is attributed to the most specific destination containing it.
        List<Path> bySpecificity = roots.stream()
                .sorted(java.util.Comparator.comparingInt(
                        (Path path) -> path.toString().length()).reversed())
                .toList();

        for (Path root : roots) {
            out.println();
            out.println("Under " + root + ":");
            for (DryRun.PlannedEntry entry : plan.entries()) {
                boolean belongsHere = bySpecificity.stream()
                        .filter(entry.path()::startsWith)
                        .findFirst()
                        .filter(root::equals)
                        .isPresent();
                if (!belongsHere) {
                    continue;
                }
                String relative = root.relativize(entry.path()).toString();
                String name = (relative.isEmpty() ? "." : relative) + (entry.directory() ? "/" : "");
                out.printf(
                        "  %-46s %-17s%s%n",
                        name,
                        FilePermissions.describe(entry.permissions()),
                        entry.note() == null ? "" : "  " + entry.note());
            }
        }

        if (options.trustMode().usesCa() && options.existingCaCertificate().isEmpty()) {
            out.println();
            out.println("Would generate a new certificate authority. Keep it off the cluster machines.");
        }
        out.println();
        out.printf(
                "Would generate %d key pair(s): %d node(s) x %d scope(s)%s.%n",
                options.nodes().size() * options.scopes().size()
                        + (options.trustMode().usesCa() && options.existingCaCertificate().isEmpty()
                                ? options.trustMode() == com.neo4j.tools.certtool.model.TrustMode.INTERMEDIATE ? 2 : 1
                                : 0),
                options.nodes().size(),
                options.scopes().size(),
                options.trustMode().usesCa() && options.existingCaCertificate().isEmpty()
                        ? ", plus the CA" : "");

        if (plan.wouldSucceed()) {
            out.println();
            out.println("No problems found. Re-run without --dry-run to proceed.");
            return EXIT_OK;
        }

        err.println();
        err.printf("%d problem(s) would stop this run:%n", plan.blockers().size());
        for (DryRun.Blocker blocker : plan.blockers()) {
            err.println("  " + blocker.description());
            err.println("      " + blocker.remedy());
        }
        return EXIT_FAILURE;
    }

    private static String describePasswordSource(Options options) {
        return switch (options.passwordMode()) {
            case PROMPT -> options.sharedPassword()
                    ? "prompt once, shared by every key"
                    : "prompt, one per node";
            case GENERATE -> "generated, one per node";
            case FILE -> "read from " + options.passwordFile().orElseThrow();
        };
    }

    private PasswordProvider createPasswordProvider(Options options, SecureRandom random)
            throws IOException {
        return switch (options.passwordMode()) {
            case PROMPT -> PasswordProvider.prompting(options.sharedPassword(), random);
            case GENERATE -> PasswordProvider.generating(random);
            case FILE -> PasswordProvider.fromFile(options.passwordFile().orElseThrow(), random);
        };
    }

    /** Loads the CA supplied with {@code --ca-cert}/{@code --ca-key}, if any. */
    private Optional<Authority> loadExistingAuthority(
            Options options, PasswordProvider passwords, SecureRandom random)
            throws IOException, GeneralSecurityException {
        if (options.existingCaCertificate().isEmpty()) {
            return Optional.empty();
        }
        Path certificateFile = options.existingCaCertificate().orElseThrow();
        Path keyFile = options.existingCaKey().orElseThrow();

        List<X509Certificate> certificates = PemFiles.readCertificates(certificateFile);
        X509Certificate certificate = certificates.getFirst();

        char[] password = options.caPasswordFile().isPresent()
                ? PasswordProvider.readSingleFrom(options.caPasswordFile().orElseThrow())
                : passwords.forSubject("the existing CA key " + keyFile);
        PrivateKey privateKey;
        try {
            privateKey = PemFiles.readPrivateKey(keyFile, password);
        } finally {
            if (options.caPasswordFile().isPresent()) {
                Arrays.fill(password, '\0');
            }
        }

        if (!PemFiles.matches(privateKey, certificate.getPublicKey(), random)) {
            throw new GeneralSecurityException(
                    "The key in " + keyFile + " does not belong to the certificate in " + certificateFile);
        }

        DistinguishedName subject = DistinguishedName.ofEncoded(
                certificate.getSubjectX500Principal().getEncoded(),
                certificate.getSubjectX500Principal().getName());
        String label = options.trustMode() == TrustMode.INTERMEDIATE ? "root CA (existing)" : "CA (existing)";
        return Optional.of(new Authority(label, certificate, privateKey, subject, false));
    }

    private void reportPasswords(PasswordProvider passwords, Reporter reporter) {
        Map<String, char[]> generated = passwords.generatedPasswords();
        if (generated.isEmpty()) {
            return;
        }
        // Printed once and never stored anywhere else by the tool, other than inside each node's
        // neo4j.conf.snippet, which Neo4j needs in clear text anyway.
        out.println();
        out.println("Generated private key passwords — record these now, they are not recoverable:");
        generated.forEach((subject, password) -> {
            // Printed via the char[] directly: new String(password) would leave an immutable copy
            // of the password on the heap that nothing can clear.
            out.printf("  %-14s ", subject);
            out.print(password);
            out.println();
        });
    }

    private void reportNextSteps(Options options, Result result, Reporter reporter) {
        reporter.blankLine();
        reporter.info("Next steps");
        int step = 1;
        if (result.authorities().stream().anyMatch(Authority::newlyCreated)) {
            reporter.info(
                    "  %d. Move %s somewhere safe and off the cluster machines. It can issue "
                            + "certificates any member will trust.",
                    step++,
                    options.outputDirectory().resolve(Layout.CA_DIRECTORY).toAbsolutePath());
        }
        reporter.info(
                "  %d. Copy each node's %s directory to that node's NEO4J_HOME, preserving "
                        + "permissions:  rsync -a %s/<node>/%s/ <host>:<neo4j-home>/%s/",
                step++,
                Layout.CERTIFICATES_DIRECTORY,
                options.outputDirectory(),
                Layout.CERTIFICATES_DIRECTORY,
                Layout.CERTIFICATES_DIRECTORY);
        reporter.info("  %d. chown -R neo4j:neo4j <neo4j-home>/%s", step++, Layout.CERTIFICATES_DIRECTORY);
        reporter.info(
                "  %d. Merge each node's %s into its conf/neo4j.conf, then restart the instance.",
                step++, Layout.CONF_SNIPPET_FILE);
        reporter.info(
                "  %d. Confirm with:  neo4j-cert-tool verify --out %s",
                step, options.outputDirectory());
    }

    // --- verify ----------------------------------------------------------------------------

    private int verify(Options options, Reporter reporter) throws IOException {
        SecureRandom random = new SecureRandom();
        try (PasswordProvider passwords = createPasswordProvider(options, random)) {
            BundleVerifier.Report report = new BundleVerifier(passwords, random, Instant.now())
                    .verify(options.outputDirectory());

            for (BundleVerifier.Finding finding : report.findings()) {
                if (finding.severity() == BundleVerifier.Severity.OK) {
                    reporter.info(finding.toString());
                } else {
                    err.println(finding);
                }
            }
            reporter.blankLine();
            if (report.hasErrors()) {
                err.printf(
                        "%d of %d checks failed.%n",
                        report.findings().stream()
                                .filter(f -> f.severity() == BundleVerifier.Severity.ERROR)
                                .count(),
                        report.checksRun());
                return EXIT_FAILURE;
            }
            reporter.print("All %d checks passed.".formatted(report.checksRun()));
            return EXIT_OK;
        }
    }

    /** The version from the jar manifest, or a placeholder when running from classes. */
    static String version() {
        String version = Main.class.getPackage().getImplementationVersion();
        return version != null ? version : "(development build)";
    }
}
