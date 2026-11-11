package com.neo4j.tools.certtool.skill;

import com.neo4j.tools.certtool.output.Reporter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

/**
 * Installs, inspects and removes agent skills.
 *
 * <p>Skills are addressed by name: the embedded self-skill as {@code self} or by the tool's own
 * name, and catalog skills by their catalog name. State is reported per skill and per agent, so a
 * multi-agent setup shows exactly which copies have drifted.
 */
public final class Skills {

    /** Version line a catalog skill carries in its marker, which has no version of its own. */
    static final String CATALOG = "catalog";

    private final SelfSkill self;
    private final Catalog catalog;
    private final List<AgentRegistry> agents;
    private final Reporter reporter;

    /**
     * @param agents the agents to operate on, already resolved from {@code --agent} or detection
     */
    public Skills(SelfSkill self, Catalog catalog, List<AgentRegistry> agents, Reporter reporter) {
        this.self = self;
        this.catalog = catalog;
        this.agents = agents;
        this.reporter = reporter;
    }

    // --- install -----------------------------------------------------------------------------

    /** Installs one named skill, or self plus every catalog skill with {@code all}. */
    public void install(Optional<String> name, boolean all, boolean refreshCatalog)
            throws IOException {
        requireAgents();
        List<SkillSource> sources = sourcesToInstall(name, all, refreshCatalog);
        for (SkillSource source : sources) {
            for (AgentRegistry agent : agents) {
                Path directory = source.installInto(agent);
                reporter.info("  installed %-24s -> %s", source.name(), directory);
            }
        }
        reporter.info(
                "Installed %d skill bundle(s) into %d agent(s).",
                (long) sources.size() * agents.size(), agents.size());
    }

    private List<SkillSource> sourcesToInstall(
            Optional<String> name, boolean all, boolean refreshCatalog) throws IOException {
        List<SkillSource> sources = new ArrayList<>();
        boolean wantSelf = all || name.isEmpty() || SelfSkill.isSelf(name.get());
        if (wantSelf) {
            sources.add(new SelfSource());
        }
        List<String> catalogNames = List.of();
        if (all) {
            catalogNames = catalogNames(refreshCatalog);
        } else if (name.isPresent() && !SelfSkill.isSelf(name.get())) {
            catalog.skillDirectory(name.get(), refreshCatalog); // fails clearly if unknown
            catalogNames = List.of(name.get());
        }
        for (String catalogName : catalogNames) {
            sources.add(new CatalogSource(catalogName));
        }
        return sources;
    }

    /**
     * The catalog's skill names, degraded to an empty list when the catalog cannot be reached and
     * nothing is cached: a catalog problem must not hide what is knowable about the self-skill.
     */
    private List<String> catalogNames(boolean refreshCatalog) {
        try {
            return catalog.names(refreshCatalog);
        } catch (IOException catalogUnavailable) {
            reporter.warn(
                    "The skill catalog is unavailable ("
                            + catalogUnavailable.getMessage()
                            + "); continuing with the self-skill only");
            return List.of();
        }
    }

    // --- list --------------------------------------------------------------------------------

    /** Prints per-(skill × agent) installation state. */
    public void list(boolean refreshCatalog) throws IOException {
        if (agents.isEmpty()) {
            reporter.print("No supported agent was detected on this machine; nothing to list.");
            reporter.print("Supported agents: " + AgentRegistry.ids());
            return;
        }
        List<String> names = new ArrayList<>();
        names.add(self.skillName());
        names.addAll(catalogNames(refreshCatalog));

        reporter.print("Skills for agents:");
        for (AgentRegistry agent : agents) {
            reporter.print("");
            reporter.print("  %s (%s)%s".formatted(
                    agent.displayName(),
                    agent.id(),
                    agent.detected() ? "" : "  [config directory not found]"));
            for (String name : names) {
                reporter.print("    %-24s %s".formatted(name, describe(agent, name)));
            }
        }
    }

    private String describe(AgentRegistry agent, String name) throws IOException {
        if (SelfSkill.isSelf(name)) {
            Optional<String> installed = self.installedVersion(agent);
            if (installed.isEmpty()) {
                return "not installed";
            }
            if (installed.get().equals(self.version())) {
                return "up to date at " + self.version();
            }
            return "drifted: installed at " + installed.get() + ", running "
                    + self.version();
        }
        Path installed = agent.skillsDirectory().resolve(name);
        if (!Files.isRegularFile(installed.resolve("SKILL.md"))) {
            return "not installed";
        }
        try {
            return contentMatches(installed, catalog.skillDirectory(name, false))
                    ? "up to date"
                    : "drifted from the cached catalog copy";
        } catch (IOException catalogUnavailable) {
            return "installed; source unavailable to compare against ("
                    + catalogUnavailable.getMessage() + ")";
        }
    }

    // --- check -------------------------------------------------------------------------------

    /**
     * Reports drift against the source of every installed skill.
     *
     * @return the number of drifted or missing-for-a-reason findings, so the caller can exit 1
     */
    public int check(boolean refreshCatalog) throws IOException {
        int drift = 0;
        requireAgents();
        reporter.print("Checking installed skills against their source:");
        for (AgentRegistry agent : agents) {
            List<String> findings = new ArrayList<>();
            Optional<String> installed = self.installedVersion(agent);
            if (installed.isEmpty()) {
                findings.add("self-skill not installed");
            } else if (!self.matchesInstalled(agent)) {
                findings.add(
                        installed.get().equals(self.version())
                                ? "self-skill was edited on disk after install. Repair with: skill"
                                        + " install " + SelfSkill.NAME
                                : "self-skill drifted: installed at " + installed.get()
                                        + ", running " + self.version() + ". Refresh with: skill"
                                        + " install " + SelfSkill.NAME);
            }
            for (String name : catalogNames(refreshCatalog)) {
                Path directory = agent.skillsDirectory().resolve(name);
                if (!Files.isRegularFile(directory.resolve("SKILL.md"))) {
                    continue; // catalog skills are opt-in; absence is normal, not drift
                }
                try {
                    if (!contentMatches(directory, catalog.skillDirectory(name, false))) {
                        findings.add(
                                "'" + name + "' differs from the cached catalog copy. Refresh"
                                        + " with: skill install " + name + " --refresh");
                    }
                } catch (IOException catalogUnavailable) {
                    findings.add(
                            "'" + name + "' cannot be compared: " + catalogUnavailable.getMessage());
                }
            }
            if (findings.isEmpty()) {
                reporter.print("  %-20s ok".formatted(agent.id()));
            } else {
                for (String finding : findings) {
                    reporter.print("  %-20s %s".formatted(agent.id(), finding));
                }
                drift += findings.size();
            }
        }
        return drift;
    }

    private static boolean contentMatches(Path installed, Path source) throws IOException {
        try (Stream<Path> installedFiles = Files.walk(installed)) {
            for (Path file : installedFiles.filter(Files::isRegularFile).toList()) {
                if (file.getFileName().toString().startsWith(".")) {
                    continue; // the marker describes the copy, it is not skill content
                }
                Path relative = installed.relativize(file);
                Path sourceCounterpart = source.resolve(relative);
                if (!Files.isRegularFile(sourceCounterpart)
                        || !java.util.Arrays.equals(
                                Files.readAllBytes(file), Files.readAllBytes(sourceCounterpart))) {
                    return false;
                }
            }
        }
        return true;
    }

    // --- remove ------------------------------------------------------------------------------

    /** Removes one named skill, or every catalog skill (the self-skill preserved) with {@code all}. */
    public void remove(Optional<String> name, boolean all) throws IOException {
        requireAgents();
        List<String> names = new ArrayList<>();
        if (all) {
            names.addAll(catalogNames(false));
        } else if (name.isPresent()) {
            names.add(name.get());
        } else {
            throw new IllegalStateException(
                    "Name a skill to remove, or pass --all to remove every catalog skill");
        }
        for (String skillName : names) {
            for (AgentRegistry agent : agents) {
                boolean removed = SelfSkill.isSelf(skillName)
                        ? self.removeFrom(agent)
                        : deleteTree(agent.skillsDirectory().resolve(skillName));
                if (removed) {
                    reporter.info("  removed %-24s from %s", skillName, agent.id());
                }
            }
        }
    }

    /** Forces a catalog fetch, ignoring the cache's freshness. */
    public void refresh() throws IOException {
        catalog.refreshIfStale(true);
        reporter.print("Catalog refreshed: %d skill(s) available."
                .formatted(catalog.names(false).size()));
    }

    // --- background refresh --------------------------------------------------------------------

    /**
     * Refreshes installed self-skill bundles whose version trails the running one.
     *
     * <p>Called only from an interactive terminal: an agent harness or script must never observe
     * the tool's skill surface change mid-task. Non-interactive runs can force it explicitly with
     * {@code skill install}.
     */
    public void autoRefresh() {
        for (AgentRegistry agent : agents) {
            try {
                Optional<String> installed = self.installedVersion(agent);
                if (installed.isPresent()
                        && !installed.get().equals(self.version())
                        && !installed.get().equals(CATALOG)) {
                    self.installInto(agent);
                    reporter.info(
                            "Skill bundle for %s refreshed to %s", agent.id(), self.version());
                }
            } catch (IOException failed) {
                reporter.warn("Could not refresh the skill bundle for " + agent.id() + ": "
                        + failed.getMessage());
            }
        }
    }

    private void requireAgents() {
        if (agents.isEmpty()) {
            throw new IllegalStateException(
                    "No supported agent was detected on this machine. Install one, or name it"
                            + " explicitly with --agent <name>. Supported: " + AgentRegistry.ids());
        }
    }

    private static boolean deleteTree(Path directory) throws IOException {
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

    /** Where a skill's content comes from, which is also what install copies. */
    private interface SkillSource {
        String name();

        Path installInto(AgentRegistry agent) throws IOException;
    }

    private class SelfSource implements SkillSource {
        @Override
        public String name() {
            return self.skillName();
        }

        @Override
        public Path installInto(AgentRegistry agent) throws IOException {
            return self.installInto(agent);
        }
    }

    /** A catalog skill: copied file for file out of the local cache. */
    private class CatalogSource implements SkillSource {
        private final String name;

        CatalogSource(String name) {
            this.name = name;
        }

        @Override
        public String name() {
            return name;
        }

        @Override
        public Path installInto(AgentRegistry agent) throws IOException {
            Path source = catalog.skillDirectory(name, false);
            Path target = agent.skillsDirectory().resolve(name);
            try (Stream<Path> files = Files.walk(source)) {
                for (Path file : files.filter(Files::isRegularFile).toList()) {
                    Path destination = target.resolve(source.relativize(file));
                    Files.createDirectories(destination.getParent());
                    Files.copy(file, destination,
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }
            }
            // The marker records which files a catalog install covered and what they contained,
            // so check can tell drift from absence. Digests are over raw bytes: a catalog skill
            // is not guaranteed to be text.
            StringBuilder digests = new StringBuilder("version=" + CATALOG + "\n");
            try (Stream<Path> files = Files.walk(target)) {
                for (Path file : files.filter(Files::isRegularFile).toList()) {
                    if (file.getFileName().toString().startsWith(".")) {
                        continue;
                    }
                    digests.append(sha256(Files.readAllBytes(file)))
                            .append(' ')
                            .append(target.relativize(file))
                            .append('\n');
                }
            }
            Files.writeString(
                    target.resolve(SelfSkill.MARKER_FILE), digests.toString(), StandardCharsets.UTF_8);
            return target;
        }
    }

    private static String sha256(byte[] content) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(content);
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
