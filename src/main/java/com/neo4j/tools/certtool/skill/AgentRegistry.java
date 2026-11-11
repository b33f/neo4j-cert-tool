package com.neo4j.tools.certtool.skill;

import java.nio.file.Path;
import java.util.List;
import java.util.Optional;

/**
 * The AI coding agents this tool can install skills for.
 *
 * <p>Each entry names the agent, the directory its documentation reads skills from, and a
 * configuration directory whose presence means the agent is installed on this machine. Detection is
 * therefore "does the agent's config directory exist" — imperfect, but it errs toward showing an
 * agent the user can immediately check, rather than hiding one.
 *
 * <p>Agent skill-directory conventions are set by each vendor and occasionally move; every path
 * lives in this one table so a correction is a one-line change.
 */
public enum AgentRegistry {

    CLAUDE_CODE("claude-code", "Claude Code", ".claude", ".claude/skills"),
    CURSOR("cursor", "Cursor", ".cursor", ".cursor/skills"),
    WINDSURF("windsurf", "Windsurf", ".codeium", ".codeium/windsurf/skills"),
    GEMINI("gemini", "Gemini CLI", ".gemini", ".gemini/skills"),
    CLINE("cline", "Cline", ".cline", ".cline/skills"),
    CODEX("codex", "Codex", ".codex", ".codex/skills"),
    OPENCODE("opencode", "OpenCode", ".config/opencode", ".config/opencode/skills"),
    COPILOT("copilot", "Copilot", ".copilot", ".copilot/skills"),
    ANTIGRAVITY("antigravity", "Antigravity", ".antigravity", ".antigravity/skills"),
    JUNIE("junie", "Junie", ".junie", ".junie/skills"),
    KIRO("kiro", "Kiro", ".kiro", ".kiro/skills"),
    PI("pi", "Pi", ".pi", ".pi/skills");

    private final String id;
    private final String displayName;
    private final String detectionDirectory;
    private final String skillsDirectory;

    AgentRegistry(String id, String displayName, String detectionDirectory, String skillsDirectory) {
        this.id = id;
        this.displayName = displayName;
        this.detectionDirectory = detectionDirectory;
        this.skillsDirectory = skillsDirectory;
    }

    /** The lower-case identifier used on the command line: {@code --agent claude-code}. */
    public String id() {
        return id;
    }

    public String displayName() {
        return displayName;
    }

    /** Where this agent reads skills from, resolved against the user's home directory. */
    public Path skillsDirectory() {
        return home().resolve(skillsDirectory);
    }

    /** Whether the agent looks installed: its configuration directory exists. */
    public boolean detected() {
        return java.nio.file.Files.isDirectory(home().resolve(detectionDirectory));
    }

    /** Every agent whose configuration directory exists on this machine. */
    public static List<AgentRegistry> detectedAgents() {
        return List.of(values()).stream().filter(AgentRegistry::detected).toList();
    }

    public static Optional<AgentRegistry> byId(String id) {
        return List.of(values()).stream()
                .filter(agent -> agent.id.equalsIgnoreCase(id))
                .findFirst();
    }

    /** Comma-separated ids, for usage messages. */
    public static String ids() {
        return List.of(values()).stream().map(agent -> agent.id).reduce((a, b) -> a + ", " + b)
                .orElse("");
    }

    private static Path home() {
        return Path.of(System.getProperty("user.home"));
    }
}
