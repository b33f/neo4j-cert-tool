package com.neo4j.tools.certtool.skill;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Checks the agent table: identifier lookup and directory derivation. */
class AgentRegistryTest {

    @TempDir
    Path home;

    private void withHome() {
        System.setProperty("user.home", home.toString());
    }

    @Test
    void resolvesIdsCaseInsensitively() {
        assertEquals(
                java.util.Optional.of(AgentRegistry.CLAUDE_CODE), AgentRegistry.byId("claude-code"));
        assertEquals(java.util.Optional.of(AgentRegistry.CLAUDE_CODE), AgentRegistry.byId("Claude-Code"));
        assertEquals(java.util.Optional.empty(), AgentRegistry.byId("emacs"));
    }

    @Test
    void detectsAnAgentByItsConfigDirectory() throws Exception {
        withHome();
        assertFalse(AgentRegistry.CLAUDE_CODE.detected());

        Files.createDirectories(home.resolve(".claude"));
        assertTrue(AgentRegistry.CLAUDE_CODE.detected());
        assertFalse(AgentRegistry.CURSOR.detected(), "another agent stays undetected");
    }

    @Test
    void derivesTheSkillsDirectoryFromTheHomeProperty() {
        withHome();

        assertEquals(
                home.resolve(".claude/skills/neo4j-cert-tool"),
                AgentRegistry.CLAUDE_CODE.skillsDirectory().resolve(SelfSkill.NAME));
    }
}
