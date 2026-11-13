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
import java.nio.file.Files;
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
        // A version change makes every installed self-skill bundle stale; interactive runs are
        // where refreshing is safe, because an agent's view of the tool surface must not move.
        // Kept off help and version, whose output should stay exact.
        if (options.command() == Options.Command.GENERATE
                || options.command() == Options.Command.VERIFY
                || options.command() == Options.Command.UPDATE) {
            autoRefreshSkills(reporter);
        }
        // The once-a-day "a newer version exists" courtesy, for the commands a person runs by
        // hand. Explicit checks belong to the update command itself.
        if ((options.command() == Options.Command.GENERATE
                        || options.command() == Options.Command.VERIFY)
                && !options.noUpdateCheck()
                && !com.neo4j.tools.certtool.update.UpdateNotice.disabledByEnvironment(
                        System.getenv(com.neo4j.tools.certtool.update.UpdateNotice.ENV_VARIABLE))
                && PasswordProvider.terminalAvailable()) {
            runUpdateNotice(reporter);
        }
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
                case UPDATE -> update(options, reporter);
                case SKILL -> skills(options, reporter);
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
        describeNameConstraints(options, reporter);
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
            var constraints = options.nameConstraints()
                    ? com.neo4j.tools.certtool.model.NameConstraints.deriveFrom(
                            options.nodes(), options.permitDns(), options.permitIp())
                    : com.neo4j.tools.certtool.model.NameConstraints.none();
            if (constraints.isEmpty()) {
                out.println("  It would be UNCONSTRAINED: able to issue a certificate for any name,");
                out.println("  including google.com. Drop --no-name-constraints to limit it.");
            } else {
                out.println("  It would be limited to issuing certificates for:");
                constraints.describe().forEach(line -> out.println("    " + line));
                out.println("  Nodes outside those limits could not be added to it later.");
            }
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

    /** Reports what a newly created CA will and will not be allowed to issue for. */
    private static void describeNameConstraints(Options options, Reporter reporter) {
        if (!options.trustMode().usesCa() || options.existingCaCertificate().isPresent()) {
            return;
        }
        if (!options.nameConstraints()) {
            reporter.info("  CA limits      none — this CA could issue a certificate for any name");
            return;
        }
        var constraints = com.neo4j.tools.certtool.model.NameConstraints.deriveFrom(
                options.nodes(), options.permitDns(), options.permitIp());
        List<String> lines = constraints.describe();
        for (int i = 0; i < lines.size(); i++) {
            reporter.info("  %-14s %s", i == 0 ? "CA limits" : "", lines.get(i));
        }
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
        reporter.info(
                "  %d. Point Java clients (cypher-shell, driver apps) at %s — the run's trust "
                        + "anchors as PKCS#12, public certificates only, password 'changeit'.",
                step++, options.outputDirectory().resolve(Layout.CLIENT_TRUSTSTORE_FILE));
        reporter.info("  %d. chown -R neo4j:neo4j <neo4j-home>/%s", step++, Layout.CERTIFICATES_DIRECTORY);
        reporter.info(
                "  %d. Merge each node's %s into its conf/neo4j.conf, then restart the instance.",
                step++, Layout.CONF_SNIPPET_FILE);
        reporter.info(
                "  %d. Confirm with:  neo4j-cert-tool verify --out %s",
                step, options.outputDirectory());
    }

    // --- verify ----------------------------------------------------------------------------

    /** The GitHub API root this tool updates itself from. Package-private so tests can pin it. */
    static final String UPDATE_API_BASE = "https://api.github.com/repos/neo4j-labs/neo4j-cert-tool";

    /** Only download URLs under this prefix are followed, in {@code update} as in the API. */
    static final String UPDATE_DOWNLOAD_PREFIX =
            "https://github.com/neo4j-labs/neo4j-cert-tool/releases/download/";

    /**
     * Checks for, or installs, a new release.
     *
     * <p>{@code update check} exits 1 when a newer version exists, so a script can gate on it; the
     * neo4j-cli convention this follows treats "newer available" as the notable answer.
     */
    private int update(Options options, Reporter reporter) throws IOException {
        var releases =
                new com.neo4j.tools.certtool.update.Releases(UPDATE_API_BASE, UPDATE_DOWNLOAD_PREFIX);
        var update = new com.neo4j.tools.certtool.update.Update(
                runningJar(),
                version(),
                releases,
                reporter,
                options.preReleases(),
                options.versionPin().orElse(null));
        var outcome = options.checkOnly() ? update.check() : update.install();
        return outcome == com.neo4j.tools.certtool.update.Update.Outcome.NEWER_AVAILABLE
                ? EXIT_FAILURE
                : EXIT_OK;
    }

    /**
     * The jar this class was loaded from, or null when running from a directory of classes, as a
     * development build does.
     */
    private static Path runningJar() {
        try {
            var location = Main.class.getProtectionDomain().getCodeSource().getLocation();
            Path path = Path.of(location.toURI());
            return Files.isRegularFile(path) ? path : null;
        } catch (Exception notAFileLocation) {
            return null;
        }
    }

    // --- skill ------------------------------------------------------------------------------

    /**
     * Installs, inspects or removes the agent skills: the embedded self-skill, or any skill from
     * the curated catalog.
     *
     * <p>{@code skill check} exits 1 when drift was found, so a script can gate on it, mirroring
     * {@code update check}.
     */
    private int skills(Options options, Reporter reporter) throws IOException {
        var self = new com.neo4j.tools.certtool.skill.SelfSkill(version());
        var catalog = new com.neo4j.tools.certtool.skill.Catalog(
                com.neo4j.tools.certtool.skill.Catalog.userCacheDirectory(),
                com.neo4j.tools.certtool.skill.Catalog.standardErrors());
        var targets = resolveAgents(options);
        var skills = new com.neo4j.tools.certtool.skill.Skills(
                self, catalog, targets, reporter);
        return switch (options.skillAction()) {
            case INSTALL -> {
                skills.install(options.skillName(), options.skillAll(), options.refreshCatalog());
                yield EXIT_OK;
            }
            case LIST -> {
                skills.list(options.refreshCatalog());
                yield EXIT_OK;
            }
            case CHECK -> {
                int drift = skills.check(options.refreshCatalog());
                if (drift == 0) {
                    reporter.print("No drift found.");
                }
                yield drift == 0 ? EXIT_OK : EXIT_FAILURE;
            }
            case REMOVE -> {
                skills.remove(options.skillName(), options.skillAll());
                yield EXIT_OK;
            }
            case REFRESH -> {
                skills.refresh();
                yield EXIT_OK;
            }
        };
    }

    /** The agents a skill action operates on: those named with {@code --agent}, or all detected. */
    private static List<com.neo4j.tools.certtool.skill.AgentRegistry> resolveAgents(Options options) {
        if (!options.agents().isEmpty()) {
            return options.agents().stream()
                    .map(id -> com.neo4j.tools.certtool.skill.AgentRegistry.byId(id).orElseThrow())
                    .toList();
        }
        return com.neo4j.tools.certtool.skill.AgentRegistry.detectedAgents();
    }

    /**
     * Refreshes installed self-skill bundles that trail the running version — but only from an
     * interactive terminal. An agent harness or script runs with its streams redirected: it must
     * never observe the tool's skill surface change in the middle of a task. Agents refresh
     * explicitly with {@code skill install}; the automatic behaviour is disabled with the
     * environment variable {@code NEO4J_CERT_TOOL_SKILL_AUTO_REFRESH=false}.
     */
    private void autoRefreshSkills(Reporter reporter) {
        if (!PasswordProvider.terminalAvailable()
                || "false".equalsIgnoreCase(System.getenv("NEO4J_CERT_TOOL_SKILL_AUTO_REFRESH"))) {
            return;
        }
        try {
            var self = new com.neo4j.tools.certtool.skill.SelfSkill(version());
            var skills = new com.neo4j.tools.certtool.skill.Skills(
                    self,
                    new com.neo4j.tools.certtool.skill.Catalog(
                            com.neo4j.tools.certtool.skill.Catalog.userCacheDirectory(),
                            com.neo4j.tools.certtool.skill.Catalog.standardErrors()),
                    com.neo4j.tools.certtool.skill.AgentRegistry.detectedAgents(),
                    reporter);
            skills.autoRefresh();
        } catch (Exception refreshFailure) {
            // Never let skill housekeeping stop the command the user actually asked for.
            reporter.warn("Skill auto-refresh failed: " + refreshFailure.getMessage());
        }
    }

    /**
     * The automatic update-availability check. Everything it does is best-effort: the notice is a
     * courtesy, so the network attempt is bounded to once a day and any failure is silent.
     */
    private void runUpdateNotice(Reporter reporter) {
        try {
            var releases = new com.neo4j.tools.certtool.update.Releases(
                    UPDATE_API_BASE, UPDATE_DOWNLOAD_PREFIX);
            var notice = new com.neo4j.tools.certtool.update.UpdateNotice(
                    com.neo4j.tools.certtool.skill.Catalog.userCacheRoot().resolve("update-check"),
                    releases,
                    version());
            notice.check().ifPresent(reporter::print);
        } catch (Exception noticeFailure) {
            // Never let the notice break the command the user actually asked for.
        }
    }

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
