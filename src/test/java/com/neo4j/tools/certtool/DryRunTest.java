package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.output.FilePermissions;
import com.neo4j.tools.certtool.output.Layout;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Covers {@code --dry-run}: that it writes nothing, and that its plan matches reality. */
class DryRunTest {

    private record Run(int exitCode, String stdout, String stderr) {
        String all() {
            return stdout + stderr;
        }
    }

    private static Run invoke(String... arguments) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int exitCode;
        try (PrintStream outStream = new PrintStream(out, true, StandardCharsets.UTF_8);
                PrintStream errStream = new PrintStream(err, true, StandardCharsets.UTF_8)) {
            exitCode = new Main(outStream, errStream).run(arguments);
        }
        return new Run(
                exitCode, out.toString(StandardCharsets.UTF_8), err.toString(StandardCharsets.UTF_8));
    }

    /** The standard arguments, with an output directory and password file inside {@code work}. */
    private static List<String> arguments(Path work, String... extra) throws Exception {
        List<String> arguments = new ArrayList<>(List.of(
                "--out", work.resolve("out").toString(),
                "--password-file", TestBundles.passwordFile(work).toString(),
                "--pbkdf2-iterations", TestBundles.TEST_ITERATIONS,
                "--node", "core1:core1.example.com,10.0.0.11",
                "--node", "core2:core2.example.com,10.0.0.12"));
        arguments.addAll(List.of(extra));
        return arguments;
    }

    /**
     * Extracts the plan from the output: relative path to claimed mode, for entries under
     * {@code root}. The plan prints each destination once as a header, then relative paths.
     */
    private static TreeMap<String, String> plannedPaths(String stdout, Path root) {
        var found = new TreeMap<String, String>();
        boolean inSection = false;
        for (String line : stdout.lines().toList()) {
            if (line.startsWith("Under ")) {
                inSection = line.equals("Under " + root + ":");
                continue;
            }
            if (!inSection || !line.startsWith("  ")) {
                continue;
            }
            String[] parts = line.strip().split("\\s+");
            if (parts.length < 2 || parts[0].equals("./")) {
                continue;
            }
            String path = parts[0].endsWith("/") ? parts[0].substring(0, parts[0].length() - 1) : parts[0];
            found.put(path, parts[1]);
        }
        return found;
    }

    @Test
    @DisplayName("writes absolutely nothing")
    void writesNothing(@TempDir Path work) throws Exception {
        Run run = invoke(arguments(work, "--dry-run").toArray(String[]::new));

        assertEquals(Main.EXIT_OK, run.exitCode(), run.all());
        assertFalse(Files.exists(work.resolve("out")), "the output directory must not be created");
        // Only the password file the fixture wrote should exist in the work directory.
        try (Stream<Path> contents = Files.list(work)) {
            assertEquals(
                    List.of("passwords.txt"),
                    contents.map(path -> path.getFileName().toString()).sorted().toList());
        }
    }

    @Test
    @DisplayName("says plainly that it is a dry run, and what would be produced")
    void explainsItself(@TempDir Path work) throws Exception {
        Run run = invoke(arguments(work, "--dry-run").toArray(String[]::new));

        assertTrue(run.stdout().contains("DRY RUN — nothing will be written."), run.stdout());
        assertTrue(run.stdout().contains("Would create"), run.stdout());
        // 2 nodes x 4 scopes, plus the CA key pair.
        assertTrue(run.stdout().contains("Would generate 9 key pair(s)"), run.stdout());
        assertTrue(run.stdout().contains("Re-run without --dry-run to proceed."), run.stdout());
    }

    @Test
    @DisplayName("lists each path with the permissions it would be given")
    void reportsPermissions(@TempDir Path work) throws Exception {
        Run run = invoke(arguments(work, "--dry-run").toArray(String[]::new));

        assertTrue(run.stdout().contains("private.key"), run.stdout());
        assertTrue(run.stdout().contains("r-------- (0400)"), "private keys are 0400");
        assertTrue(run.stdout().contains("rw-r--r-- (0644)"), "certificates are 0644");
        assertTrue(run.stdout().contains("rwxr-xr-x (0755)"), "policy directories are 0755");
        assertTrue(run.stdout().contains("rwx------ (0700)"), "the staging tree is 0700");
    }

    @ParameterizedTest
    @ValueSource(strings = {"ca", "intermediate", "self-signed"})
    @DisplayName("the plan matches exactly what a real run creates")
    void planMatchesReality(String mode, @TempDir Path work) throws Exception {
        // The point of this test: the planner and the writer derive paths independently, so they
        // could drift. Comparing a plan against an actual run is what stops that.
        Path planned = Files.createDirectory(work.resolve("planned"));
        Path actual = Files.createDirectory(work.resolve("actual"));

        Run dry = invoke(arguments(planned, "--mode", mode, "--dry-run").toArray(String[]::new));
        assertEquals(Main.EXIT_OK, dry.exitCode(), dry.all());

        Run real = invoke(arguments(actual, "--mode", mode).toArray(String[]::new));
        assertEquals(Main.EXIT_OK, real.exitCode(), real.all());

        Path plannedRoot = planned.resolve("out");
        List<String> fromPlan = plannedPaths(dry.stdout(), plannedRoot).keySet().stream().sorted().toList();

        Path actualRoot = actual.resolve("out");
        List<String> fromDisk;
        try (Stream<Path> walk = Files.walk(actualRoot)) {
            fromDisk = walk.map(actualRoot::relativize)
                    .map(Path::toString)
                    .filter(relative -> !relative.isEmpty())
                    .sorted()
                    .toList();
        }

        assertEquals(fromDisk, fromPlan, "mode " + mode + ": the plan and the real output must agree");
    }

    @Test
    @DisplayName("the planned permissions match the permissions actually applied")
    void plannedPermissionsMatchReality(@TempDir Path work) throws Exception {
        org.junit.jupiter.api.Assumptions.assumeTrue(FilePermissions.posixSupported());

        Path planned = Files.createDirectory(work.resolve("planned"));
        Path actual = Files.createDirectory(work.resolve("actual"));

        Run dry = invoke(arguments(planned, "--dry-run").toArray(String[]::new));
        invoke(arguments(actual).toArray(String[]::new));

        Path plannedRoot = planned.resolve("out");
        var claimed = plannedPaths(dry.stdout(), plannedRoot);

        Path actualRoot = actual.resolve("out");
        for (var entry : claimed.entrySet()) {
            if (entry.getKey().isEmpty()) {
                continue;
            }
            Set<java.nio.file.attribute.PosixFilePermission> onDisk =
                    FilePermissions.read(actualRoot.resolve(entry.getKey()));
            assertEquals(
                    entry.getValue(),
                    java.nio.file.attribute.PosixFilePermissions.toString(onDisk),
                    entry.getKey() + ": planned mode must match what was applied");
        }
    }

    @Test
    @DisplayName("detects a non-empty output directory that would block the run")
    void detectsBlockedOutputDirectory(@TempDir Path work) throws Exception {
        // The case in the brief: something is already there, so a real run would refuse.
        Path out = Files.createDirectories(work.resolve("out"));
        Files.writeString(out.resolve("something.txt"), "in the way");

        Run run = invoke(arguments(work, "--dry-run").toArray(String[]::new));

        assertEquals(Main.EXIT_FAILURE, run.exitCode(), "a blocked run must not report success");
        assertTrue(run.stderr().contains("is not empty"), run.stderr());
        assertTrue(run.stderr().contains("--force"), "the remedy must be stated: " + run.stderr());
    }

    @Test
    @DisplayName("a blocked run reports success once --force is added")
    void forceClearsTheBlocker(@TempDir Path work) throws Exception {
        Path out = Files.createDirectories(work.resolve("out"));
        Files.writeString(out.resolve("something.txt"), "in the way");

        Run run = invoke(arguments(work, "--dry-run", "--force").toArray(String[]::new));

        assertEquals(Main.EXIT_OK, run.exitCode(), run.all());
        assertTrue(run.stdout().contains("No problems found"), run.stdout());
    }

    @Test
    @DisplayName("detects an install target that already holds a policy directory")
    void detectsBlockedInstall(@TempDir Path work) throws Exception {
        Path neo4jHome = Files.createDirectory(work.resolve("neo4j"));
        Files.createDirectories(Layout.scope(neo4jHome, Scope.BOLT));
        Files.writeString(Layout.publicCertificate(neo4jHome, Scope.BOLT), "in use by a live cluster");

        Run run = invoke(arguments(
                        work,
                        "--dry-run",
                        "--install-node", "core1",
                        "--neo4j-home", neo4jHome.toString())
                .toArray(String[]::new));

        assertEquals(Main.EXIT_FAILURE, run.exitCode());
        assertTrue(run.stderr().contains("bolt policy directory"), run.stderr());
        // And it must not have touched the live installation.
        assertEquals(
                "in use by a live cluster",
                Files.readString(Layout.publicCertificate(neo4jHome, Scope.BOLT)));
    }

    @Test
    @DisplayName("detects a missing password file")
    void detectsMissingPasswordFile(@TempDir Path work) throws Exception {
        Run run = invoke(
                "--out", work.resolve("out").toString(),
                "--password-file", work.resolve("absent.txt").toString(),
                "--node", "core1:core1.example.com",
                "--dry-run");

        assertEquals(Main.EXIT_FAILURE, run.exitCode());
        assertTrue(run.stderr().contains("cannot be read"), run.stderr());
    }

    @Test
    @DisplayName("detects a malformed password file before a real run would fail on it")
    void detectsMalformedPasswordFile(@TempDir Path work) throws Exception {
        Path passwords = work.resolve("bad.txt");
        Files.writeString(passwords, "a-bare-password\ncore1=another-password\n");

        Run run = invoke(
                "--out", work.resolve("out").toString(),
                "--password-file", passwords.toString(),
                "--node", "core1:core1.example.com",
                "--dry-run");

        assertEquals(Main.EXIT_FAILURE, run.exitCode());
        assertTrue(run.stderr().contains("not usable"), run.stderr());
    }

    @Test
    @DisplayName("detects a missing CA when issuing from an existing one")
    void detectsMissingCa(@TempDir Path work) throws Exception {
        Run run = invoke(arguments(
                        work,
                        "--dry-run",
                        "--ca-cert", work.resolve("absent.crt").toString(),
                        "--ca-key", work.resolve("absent.key").toString())
                .toArray(String[]::new));

        assertEquals(Main.EXIT_FAILURE, run.exitCode());
        assertTrue(run.stderr().contains("CA certificate"), run.stderr());
        assertTrue(run.stderr().contains("CA private key"), run.stderr());
    }

    @Test
    @DisplayName("reports every blocker at once, not just the first")
    void reportsAllBlockers(@TempDir Path work) throws Exception {
        Path out = Files.createDirectories(work.resolve("out"));
        Files.writeString(out.resolve("something.txt"), "in the way");

        Run run = invoke(
                "--out", out.toString(),
                "--password-file", work.resolve("absent.txt").toString(),
                "--node", "core1:core1.example.com",
                "--dry-run");

        assertEquals(Main.EXIT_FAILURE, run.exitCode());
        assertTrue(run.stderr().contains("2 problem(s)"), run.stderr());
    }

    @Test
    @DisplayName("reusing an existing CA plans no new CA directory")
    void reusingACaPlansNoCaDirectory(@TempDir Path work) throws Exception {
        // Generate a real CA to point at.
        Path first = Files.createDirectory(work.resolve("first"));
        TestBundles.Run existing = TestBundles.twoNodeCluster(first, "ca");

        Path second = Files.createDirectory(work.resolve("second"));
        Run run = invoke(arguments(
                        second,
                        "--dry-run",
                        "--ca-cert", existing.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE).toString(),
                        "--ca-key", existing.caDirectory().resolve(Layout.CA_KEY_FILE).toString(),
                        "--ca-password-file", TestBundles.passwordFile(first).toString())
                .toArray(String[]::new));

        assertEquals(Main.EXIT_OK, run.exitCode(), run.all());
        assertFalse(run.stdout().contains("Would generate a new certificate authority"), run.stdout());
        assertFalse(
                withForwardSlashes(run.stdout()).contains("ca/ca.key"),
                "no CA directory should be planned: " + run.stdout());
    }

    @Test
    @DisplayName("only the selected scopes appear in the plan")
    void respectsScopeSelection(@TempDir Path work) throws Exception {
        Run run = invoke(arguments(work, "--dry-run", "--scopes", "bolt,https").toArray(String[]::new));

        String plan = withForwardSlashes(run.stdout());
        assertTrue(plan.contains("certificates/bolt"), run.stdout());
        assertTrue(plan.contains("certificates/https"), run.stdout());
        assertFalse(plan.contains("certificates/cluster"), run.stdout());
        assertFalse(plan.contains("certificates/backup"), run.stdout());
    }

    /**
     * Normalises path separators so a path assertion means the same thing on every platform.
     *
     * <p>The plan prints paths with the platform's own separator, which is what a user should see —
     * {@code core1\certificates\bolt} on Windows. Comparing against a hard-coded {@code /} made this
     * suite pass on POSIX and fail on Windows, and quietly turned the negative assertions here into
     * vacuous ones there.
     */
    private static String withForwardSlashes(String text) {
        return text.replace('\\', '/');
    }
}
