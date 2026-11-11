package com.neo4j.tools.certtool.update;

import com.neo4j.tools.certtool.output.FilePermissions;
import com.neo4j.tools.certtool.output.Reporter;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Locale;
import java.util.Optional;

/**
 * Swaps the running jar for another release.
 *
 * <p>Only the jar is replaced. The wrapper scripts locate it by relative path and carry no version
 * logic, so they survive an update untouched. The downloaded jar is verified against the release's
 * SHA256SUMS.txt before anything replaces the running file, and the replacement itself is an atomic
 * rename where the file system allows one.
 */
public final class Update {

    /** What an {@code update} run decided. */
    public enum Outcome {
        /** The running version is the newest acceptable release. */
        UP_TO_DATE,
        /** A newer release exists; reported by {@code check}, which downloads nothing. */
        NEWER_AVAILABLE,
        /** The running jar was replaced. */
        UPDATED
    }

    private final Path jarPath;
    private final Optional<Version> runningVersion;
    private final Reporter reporter;
    private final Releases releases;
    private final boolean preReleases;
    private final String versionPin;

    /**
     * @param jarPath the file to replace, or null when running from a development build
     * @param currentVersionText the version the jar reports, verbatim
     * @param releases the release feed to consult, overridable so tests can serve a fake
     * @param preReleases whether alpha, beta and rc tags are acceptable targets
     * @param versionPin the tag to move to, overriding the latest-release logic; may be null
     */
    public Update(
            Path jarPath,
            String currentVersionText,
            Releases releases,
            Reporter reporter,
            boolean preReleases,
            String versionPin) {
        this.jarPath = jarPath;
        this.runningVersion = Version.parse(currentVersionText);
        this.reporter = reporter;
        this.releases = releases;
        this.preReleases = preReleases;
        this.versionPin = versionPin;
    }

    /** Reports whether a newer release exists. Downloads nothing. */
    public Outcome check() throws IOException {
        Releases.Release release = resolveRelease();
        if (runningVersion.isEmpty()) {
            reporter.print(
                    "Latest release: " + release.tag()
                            + " (a development build cannot be compared against it)");
            return Outcome.UP_TO_DATE;
        }
        if (isNotNewer(release)) {
            reporter.print("Up to date: " + runningVersion.get() + " is the latest"
                            + acceptable(release));
            return Outcome.UP_TO_DATE;
        }
        reporter.print(
                "Update available: " + release.tag() + " is newer than the running "
                        + runningVersion.get());
        return Outcome.NEWER_AVAILABLE;
    }

    /** Downloads, verifies and swaps in the target release. */
    public Outcome install() throws IOException {
        if (jarPath == null) {
            throw new IllegalStateException(
                    "Running from a development build, so there is no jar to swap. "
                            + "Rebuild with: mvn package");
        }
        Releases.Release release = resolveRelease();
        if (!isPinned() && isNotNewer(release)) {
            reporter.print("Up to date: " + runningVersion.get() + " is the latest"
                            + acceptable(release));
            return Outcome.UP_TO_DATE;
        }
        if (isPinned() && runningVersion.isPresent() && runningVersion.get().equals(versionOf(release))) {
            reporter.print("Already at " + release.tag());
            return Outcome.UP_TO_DATE;
        }

        Path download = jarPath.resolveSibling(jarPath.getFileName() + ".download");
        try {
            String expected = expectedDigest(release);
            byte[] actual = downloadAndDigest(release, download);

            if (!MessageDigest.isEqual(hex(actual).getBytes(), expected.getBytes())) {
                throw new IOException(
                        "The downloaded " + release.jarName() + " did not match the checksum in "
                                + "the release's SHA256SUMS.txt. It has not been installed; if this "
                                + "persists, treat the release as suspect and report it.");
            }

            swap(download);
        } catch (IOException e) {
            try {
                Files.deleteIfExists(download);
            } catch (IOException cleanup) {
                // The primary failure is the one worth reporting.
            }
            throw e;
        }

        reporter.print("Updated to " + release.tag() + ": " + jarPath);
        reporter.print("Confirm with: neo4j-cert-tool version");
        return Outcome.UPDATED;
    }

    // --- resolving what to move to -----------------------------------------------------------

    private Releases.Release resolveRelease() throws IOException {
        String pin = versionPin;
        if (pin != null) {
            return releases.byTag(pin);
        }
        return releases.latest(preReleases);
    }

    private boolean isNotNewer(Releases.Release release) {
        if (runningVersion.isEmpty()) {
            // Nothing to compare against: never refuse an update for lack of a version.
            return false;
        }
        return runningVersion.get().compareTo(versionOf(release)) >= 0;
    }

    private boolean isPinned() {
        return versionPin != null;
    }

    private static String acceptable(Releases.Release release) {
        boolean preRelease = Version.parse(release.tag())
                .map(version -> !version.isStable())
                .orElse(false);
        return preRelease ? " (pre-release)" : "";
    }

    private Version versionOf(Releases.Release release) {
        return Version.parse(release.tag())
                .orElseThrow(() -> new IllegalStateException("Release tag was not validated"));
    }

    // --- downloading and swapping --------------------------------------------------------------

    /** The digest recorded for the jar asset in the release's SHA256SUMS.txt. */
    private String expectedDigest(Releases.Release release) throws IOException {
        String sums = releases.downloadText(release.sha256SumsUrl());
        for (String line : sums.split("\n")) {
            // The standard format: "<hex digest>", two spaces, "<file name>".
            String stripped = line.strip();
            int separator = stripped.indexOf(' ');
            if (separator < 0) {
                continue;
            }
            String name = stripped.substring(separator).stripLeading();
            if (name.equals(release.jarName())) {
                String digest = stripped.substring(0, separator).strip();
                if (!digest.matches("[0-9a-fA-F]{64}")) {
                    throw new IOException(
                            "SHA256SUMS.txt holds a malformed digest for " + release.jarName());
                }
                return digest.toLowerCase(Locale.ROOT);
            }
        }
        throw new IOException(
                "SHA256SUMS.txt does not mention " + release.jarName() + "; nothing to verify against");
    }

    /** Streams the jar to {@code download}, returning the SHA-256 digest of what landed. */
    private byte[] downloadAndDigest(Releases.Release release, Path download) throws IOException {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("Every JDK ships SHA-256", impossible);
        }
        try (InputStream in = releases.downloadStream(release.jarUrl())) {
            try (var out = Files.newByteChannel(
                    download,
                    java.nio.file.StandardOpenOption.CREATE_NEW,
                    java.nio.file.StandardOpenOption.WRITE)) {
                byte[] buffer = new byte[8192];
                int read;
                while ((read = in.read(buffer)) >= 0) {
                    digest.update(buffer, 0, read);
                    out.write(java.nio.ByteBuffer.wrap(buffer, 0, read));
                }
            }
        } catch (IOException e) {
            throw new IOException("Downloading " + release.jarUrl() + " failed: " + e.getMessage(), e);
        }
        return digest.digest();
    }

    /**
     * Replaces the running jar with the verified download.
     *
     * <p>The download carries the old file's permissions before the move, so an update never
     * loosens them. Where the file system cannot rename over a file another thread holds open
     * (Windows does for a running jar), the old jar is moved aside first and restored if the new
     * one cannot take its place.
     */
    private void swap(Path download) throws IOException {
        if (FilePermissions.posixSupported()) {
            var permissions = FilePermissions.read(jarPath);
            if (!permissions.isEmpty()) {
                Files.setPosixFilePermissions(download, permissions);
            }
        }
        try {
            Files.move(
                    download, jarPath,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException cannotReplace) {
            // AtomicMoveNotSupportedException and a lock held by the running instance on
            // Windows both land here.
            Path aside = jarPath.resolveSibling(jarPath.getFileName() + ".old");
            try {
                Files.move(jarPath, aside);
            } catch (IOException e) {
                throw new IOException(
                        "Cannot replace the running jar "
                                + jarPath
                                + ": it may be locked by another process. "
                                + "Close running instances and retry, or replace it by hand from "
                                + download,
                        e);
            }
            try {
                Files.move(download, jarPath, StandardCopyOption.REPLACE_EXISTING);
            } catch (IOException e) {
                Files.move(aside, jarPath); // put the original back before reporting
                throw new IOException(
                        "Replaced-jar move failed after the old jar was set aside; "
                                + "the original has been restored. Error: " + e.getMessage(),
                        e);
            }
            try {
                Files.deleteIfExists(aside);
            } catch (IOException leftover) {
                reporter.warn("Could not remove the superseded jar at " + aside);
            }
        }
    }

    private static String hex(byte[] digest) {
        StringBuilder text = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            text.append("%02x".formatted(b));
        }
        return text.toString();
    }
}
