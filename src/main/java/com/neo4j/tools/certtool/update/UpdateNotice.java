package com.neo4j.tools.certtool.update;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.DateTimeException;
import java.util.Optional;

/**
 * The once-a-day check that tells the user a newer version exists.
 *
 * <p>Runs only where it is welcome: on an interactive terminal, for the commands a user drives by
 * hand. It costs at most one request per day, because the timestamp is written <em>before</em> the
 * network is asked — a machine with no connectivity pays one short attempt per day, never a
 * per-run one. Everything about the check is allowed to fail quietly: it is a courtesy, and the
 * command the user actually asked for must never be delayed by more than its one attempt or
 * spoiled by its failure.
 */
public final class UpdateNotice {

    /** How often the automatic check may run. */
    private static final Duration INTERVAL = Duration.ofHours(24);

    /** Environment variable that turns the check off: set it to {@code false}. */
    public static final String ENV_VARIABLE = "NEO4J_CERT_TOOL_UPDATE_CHECK";

    private final Path stampFile;
    private final Releases releases;
    private final Optional<Version> runningVersion;

    /** @param stampFile where the last-check timestamp is kept across runs */
    public UpdateNotice(Path stampFile, Releases releases, String currentVersionText) {
        this.stampFile = stampFile;
        this.releases = releases;
        this.runningVersion = Version.parse(currentVersionText);
    }

    /** Whether the environment has switched the check off. */
    public static boolean disabledByEnvironment(String envValue) {
        return "false".equalsIgnoreCase(envValue == null ? "" : envValue.strip());
    }

    /** Whether a check is due: the stamp is absent, stale, or unreadable. */
    public boolean due() {
        if (runningVersion.isEmpty()) {
            return false; // a development build cannot be compared against anything
        }
        if (!Files.isRegularFile(stampFile)) {
            return true;
        }
        try {
            Instant last = Instant.parse(Files.readString(stampFile, StandardCharsets.UTF_8).strip());
            return last.plus(INTERVAL).isBefore(Instant.now());
        } catch (IOException | DateTimeException unreadable) {
            return true;
        }
    }

    /**
     * Runs the check if it is due, and returns the notice to print — empty when the user is
     * current, the check is not due, or anything went wrong.
     *
     * <p>The timestamp is recorded first, so the day's single attempt is spent whether or not it
     * succeeds.
     */
    public Optional<String> check() {
        if (!due()) {
            return Optional.empty();
        }
        markChecked();
        try {
            Releases.Release release = releases.latest(false);
            if (runningVersion.get().compareTo(Version.parse(release.tag()).orElseThrow()) >= 0) {
                return Optional.empty();
            }
            return Optional.of(
                    "A newer version is available: " + release.tag() + " (running "
                            + runningVersion.get() + "). Run 'neo4j-cert-tool update' to install.");
        } catch (IOException | RuntimeException quietFailure) {
            return Optional.empty(); // a courtesy that failed is silent
        }
    }

    private void markChecked() {
        try {
            Files.createDirectories(stampFile.getParent());
            Files.writeString(stampFile, Instant.now().toString(), StandardCharsets.UTF_8);
        } catch (IOException unwritable) {
            // Without a writable stamp the check would run once per invocation; still correct,
            // and nothing worth troubling the user about.
        }
    }
}
