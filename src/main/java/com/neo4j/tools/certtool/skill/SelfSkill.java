package com.neo4j.tools.certtool.skill;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * The skill this tool carries about itself, taught to AI coding agents.
 *
 * <p>The bundle is a directory of resources packaged inside the jar: a {@code SKILL.md} with
 * frontmatter, plus one reference per subcommand. Installing copies the resources into an agent's
 * skills directory under the skill's own name, and drops a marker file recording the tool version
 * and the digest of every installed file, so {@code skill check} can detect drift later.
 */
public final class SelfSkill {

    /** Canonical skill name; also addressable on the command line by {@link #ALIAS}. */
    public static final String NAME = "neo4j-cert-tool";

    /** The tool's own binary name resolves to the self-skill, as {@code skill install <alias>}. */
    public static final String ALIAS = "neo4j-cert-tool";

    /** Marker file recording the version and file digests of an installed copy. */
    public static final String MARKER_FILE = ".installed-by-neo4j-cert-tool";

    private static final String RESOURCE_ROOT = "/skill/" + NAME + "/";

    /** The bundle, in resource-path order. Hand-enumerated: a running jar cannot be listed. */
    private static final List<String> FILES = List.of(
            "SKILL.md",
            "references/generate.md",
            "references/verify.md",
            "references/update.md",
            "references/security.md");

    private final String version;

    /** @param version the running tool version, recorded in the marker and used for drift */
    public SelfSkill(String version) {
        this.version = version;
    }

    /** The tool version the currently running skill content comes from. */
    public String version() {
        return version;
    }

    /** Whether a name on the command line selects the self-skill. */
    public static boolean isSelf(String name) {
        return NAME.equalsIgnoreCase(name) || ALIAS.equalsIgnoreCase(name) || "self".equalsIgnoreCase(name);
    }

    /** The skill's name as it appears to the agent: the folder the bundle installs into. */
    public String skillName() {
        return NAME;
    }

    /** Reads one bundle file as text. */
    public String file(String relativePath) throws IOException {
        try (InputStream in = SelfSkill.class.getResourceAsStream(RESOURCE_ROOT + relativePath)) {
            if (in == null) {
                throw new IOException("The packaged skill is missing " + relativePath);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    /**
     * Copies the bundle into an agent's skills directory, replacing any copy this tool installed.
     *
     * @return the directory the bundle was installed into
     */
    public Path installInto(AgentRegistry agent) throws IOException {
        Path directory = agent.skillsDirectory().resolve(NAME);
        Files.createDirectories(directory.resolve("references"));
        for (String file : FILES) {
            Path target = directory.resolve(file);
            Files.createDirectories(target.getParent());
            Files.writeString(target, file(file), StandardCharsets.UTF_8);
        }
        Files.writeString(directory.resolve(MARKER_FILE), marker(), StandardCharsets.UTF_8);
        return directory;
    }

    /**
     * The version recorded in an installed copy's marker: the version line only, not the file
     * digests the marker also carries. Catalog-installed bundles record {@code catalog}.
     */
    public java.util.Optional<String> installedVersion(AgentRegistry agent) throws IOException {
        Path marker = agent.skillsDirectory().resolve(NAME).resolve(MARKER_FILE);
        if (!Files.isRegularFile(marker)) {
            return java.util.Optional.empty();
        }
        for (String line : Files.readString(marker, StandardCharsets.UTF_8).split("\n")) {
            String stripped = line.strip();
            if (stripped.startsWith("version=")) {
                return java.util.Optional.of(stripped.substring("version=".length()).strip());
            }
        }
        return java.util.Optional.empty();
    }

    /**
     * The marker contents for the running version: the version line, then one
     * {@code <sha256> <file>} line per bundle file.
     */
    public String marker() throws IOException {
        StringBuilder text = new StringBuilder("version=").append(version).append('\n');
        for (String file : FILES) {
            text.append(sha256(file(file))).append(' ').append(file).append('\n');
        }
        return text.toString();
    }

    /**
     * Whether an installed bundle is current with this instance's version and content.
     *
     * <p>The marker is not trusted on its own: every digest it records is recomputed from the
     * installed file, so a hand-edited bundle is drift even when the marker survived untouched.
     */
    public boolean matchesInstalled(AgentRegistry agent) throws IOException {
        Path directory = agent.skillsDirectory().resolve(NAME);
        Path marker = directory.resolve(MARKER_FILE);
        if (!Files.isRegularFile(marker)) {
            return false;
        }
        String installedMarker = Files.readString(marker, StandardCharsets.UTF_8);
        if (!marker().strip().equals(installedMarker.strip())) {
            return false; // covers the version line and every recorded digest
        }
        // And the files must still hash to what was recorded at install time.
        for (String line : installedMarker.split("\n")) {
            String stripped = line.strip();
            if (stripped.isEmpty() || stripped.startsWith("version=")) {
                continue;
            }
            int separator = stripped.indexOf(' ');
            Path file = directory.resolve(stripped.substring(separator + 1).strip());
            String recordedDigest = stripped.substring(0, separator);
            if (!Files.isRegularFile(file)
                    || !sha256(Files.readString(file, StandardCharsets.UTF_8))
                            .equals(recordedDigest)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Removes an installed copy, including the marker.
     *
     * @return whether there was one to remove
     */
    public boolean removeFrom(AgentRegistry agent) throws IOException {
        Path directory = agent.skillsDirectory().resolve(NAME);
        if (!Files.isDirectory(directory)) {
            return false;
        }
        try (var paths = Files.walk(directory)) {
            paths.sorted(java.util.Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException e) {
                    throw new java.io.UncheckedIOException(e);
                }
            });
        }
        return true;
    }

    private static String sha256(String content) {
        try {
            byte[] digest =
                    MessageDigest.getInstance("SHA-256").digest(content.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder(digest.length * 2);
            for (byte b : digest) {
                hex.append("%02x".formatted(b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("Every JDK ships SHA-256", impossible);
        }
    }
}
