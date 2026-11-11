package com.neo4j.tools.certtool.skill;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.output.Reporter;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Exercises the skill system: the embedded self-skill's install and drift detection, and the
 * catalog's fetch, caching and fallback behaviour, against a local server impersonating the
 * GitHub API.
 */
class SkillTest {

    private static final String REPO_PATH = "/repos/neo4j-contrib/neo4j-skills";

    @TempDir
    Path temp;

    private Path home;
    private String previousHome;
    private Path cache;
    private HttpServer server;
    private int requests;
    private final List<String> warnings = new ArrayList<>();
    private final ByteArrayOutputStream printed = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errored = new ByteArrayOutputStream();

    @BeforeEach
    void setUp() throws IOException {
        previousHome = System.getProperty("user.home");
        home = temp.resolve("home");
        cache = temp.resolve("cache");
        // Detected agents derive from user.home at call time, so point it at the fixture and
        // mark one agent installed.
        System.setProperty("user.home", home.toString());
        Files.createDirectories(home.resolve(".claude"));

        server = HttpServer.create(new java.net.InetSocketAddress("localhost", 0), 0);
        server.createContext(REPO_PATH, this::serveCatalog);
        server.start();
    }

    @AfterEach
    void tearDown() {
        System.setProperty("user.home", previousHome);
        server.stop(0);
    }

    private String apiBase() {
        return "http://localhost:" + server.getAddress().getPort() + REPO_PATH;
    }

    /** The fake catalog: two skills, each a directory holding one SKILL.md. */
    private void serveCatalog(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
        requests++;
        String path = exchange.getRequestURI().getPath();
        String body;
        if (path.equals(REPO_PATH + "/git/trees/HEAD")) {
            body = """
                {"tree": [
                   {"path": "cypher-basics", "type": "tree"},
                   {"path": "cypher-basics/SKILL.md", "type": "blob"},
                   {"path": "cypher-basics/references/examples.md", "type": "blob"},
                   {"path": "graph-modeling", "type": "tree"},
                   {"path": "graph-modeling/SKILL.md", "type": "blob"},
                   {"path": "README.md", "type": "blob"}
                 ]}
                """;
        } else if (path.equals(REPO_PATH + "/contents/cypher-basics/SKILL.md")) {
            // Quotes inside the markdown become JSON escapes, which the scanner must step over.
            body = contentDocument("# Cypher \"basics\" for\nnew agents");
        } else if (path.equals(REPO_PATH + "/contents/cypher-basics/references/examples.md")) {
            body = contentDocument("MATCH (n) RETURN n");
        } else if (path.equals(REPO_PATH + "/contents/graph-modeling/SKILL.md")) {
            body = contentDocument("# Graph modeling");
        } else {
            exchange.sendResponseHeaders(404, -1);
            return;
        }
        exchange.sendResponseHeaders(200, body.length());
        try (var out = exchange.getResponseBody()) {
            out.write(body.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String contentDocument(String markdown) {
        return "{\"content\": \""
                + Base64.getMimeEncoder().encodeToString(markdown.getBytes(StandardCharsets.UTF_8))
                + "\"}";
    }

    private Catalog catalog() {
        return new Catalog(apiBase(), cache, warnings::add);
    }

    /** Ages the catalog cache's freshness stamp, so the next unforced call must refetch. */
    private void backdateStamp(Duration age) throws IOException {
        Files.writeString(
                cache.resolve(".fetched-at"),
                java.time.Instant.now().minus(age).toString(),
                StandardCharsets.UTF_8);
    }

    private Reporter reporter() {
        return new Reporter(new PrintStream(printed), new PrintStream(errored), false);
    }

    private Skills skills() {
        return new Skills(
                new SelfSkill("1.2.1"),
                catalog(),
                AgentRegistry.detectedAgents(),
                reporter());
    }

    @Nested
    @DisplayName("the self-skill")
    class SelfSkillBundle {

        @Test
        void installsIntoADetectedAgentAndReportsItsVersion() throws IOException {
            var self = new SelfSkill("1.2.1");

            Path directory = self.installInto(AgentRegistry.CLAUDE_CODE);

            assertTrue(Files.isRegularFile(directory.resolve("SKILL.md")));
            assertTrue(
                    Files.readString(directory.resolve("SKILL.md"), StandardCharsets.UTF_8)
                            .startsWith("---"),
                    "the frontmatter survives the copy");
            assertTrue(Files.isRegularFile(directory.resolve("references/generate.md")));
            assertEquals(
                    java.util.Optional.of("1.2.1"), self.installedVersion(AgentRegistry.CLAUDE_CODE));
            assertTrue(self.matchesInstalled(AgentRegistry.CLAUDE_CODE));
        }

        @Test
        void detectsDriftWhenTheInstalledContentIsEdited() throws IOException {
            var self = new SelfSkill("1.2.1");
            self.installInto(AgentRegistry.CLAUDE_CODE);

            Files.writeString(
                    AgentRegistry.CLAUDE_CODE.skillsDirectory()
                            .resolve(SelfSkill.NAME)
                            .resolve("SKILL.md"),
                    "hand-edited",
                    StandardCharsets.UTF_8);

            assertFalse(
                    self.matchesInstalled(AgentRegistry.CLAUDE_CODE),
                    "an edited bundle must be reported as drifted");
        }

        @Test
        void detectsDriftWhenTheRunningVersionChanges() throws IOException {
            new SelfSkill("1.2.1").installInto(AgentRegistry.CLAUDE_CODE);

            assertFalse(
                    new SelfSkill("1.3.0").matchesInstalled(AgentRegistry.CLAUDE_CODE),
                    "a version bump makes the installed bundle stale");
        }

        @Test
        void isAddressableAsSelfOrByTheToolName() {
            assertTrue(SelfSkill.isSelf("self"));
            assertTrue(SelfSkill.isSelf("neo4j-cert-tool"));
            assertFalse(SelfSkill.isSelf("cypher-basics"));
        }
    }

    @Nested
    @DisplayName("the catalog")
    class CatalogFetch {

        @Test
        void fetchesAndCachesTheSkillNames() throws IOException {
            List<String> names = catalog().names(false);

            assertEquals(List.of("cypher-basics", "graph-modeling"), names);
            int afterFirst = requests;

            catalog().names(false);

            assertEquals(afterFirst, requests, "a fresh cache is not refetched");
        }

        @Test
        void fallsBackToTheCacheWhenTheNetworkFails() throws IOException {
            catalog().names(false);

            // A forced refresh against a port nothing listens on, with the same cache — the
            // path a stale cache takes when the catalog cannot be reached.
            var unreachable = new Catalog(
                    "http://localhost:1/repos/neo4j-contrib/neo4j-skills", cache, warnings::add);

            assertEquals(List.of("cypher-basics", "graph-modeling"), unreachable.names(true));
            assertEquals(1, warnings.size(), "the fallback announces itself on standard error");
        }

        @Test
        void failsClearlyWithNoCacheAndNoNetwork() {
            var unreachable = new Catalog(
                    "http://localhost:1/repos/neo4j-contrib/neo4j-skills", cache, warnings::add);

            var failure = assertThrows(IOException.class, () -> unreachable.names(false));
            assertTrue(failure.getMessage().contains("nothing is cached"), failure.getMessage());
        }

        @Test
        void refetchesWhenTheCacheGoesStale() throws IOException {
            catalog().names(false);
            int afterFirstFetch = requests;

            backdateStamp(Duration.ofHours(25));
            catalog().names(false);

            assertTrue(requests > afterFirstFetch, "a cache past its TTL is fetched again");
        }

        @Test
        void fallsBackToAStaleCacheWhenTheNetworkFails() throws IOException {
            catalog().names(false);
            backdateStamp(Duration.ofHours(25)); // stale, but present

            var unreachable = new Catalog(
                    "http://localhost:1/repos/neo4j-contrib/neo4j-skills", cache, warnings::add);

            assertEquals(List.of("cypher-basics", "graph-modeling"), unreachable.names(false));
            assertEquals(1, warnings.size(), "the fallback announces itself on standard error");
        }

        @Test
        void refetchesPastAnUnreadableTimestamp() throws IOException {
            catalog().names(false);
            int afterFirstFetch = requests;

            Files.writeString(
                    cache.resolve(".fetched-at"), "not a timestamp", StandardCharsets.UTF_8);
            catalog().names(false);

            assertTrue(requests > afterFirstFetch, "a corrupt stamp must not pin the cache");
        }

        @Test
        void rejectsAnUnknownSkillName() throws IOException {
            catalog().names(false);

            var failure = assertThrows(
                    IOException.class, () -> catalog().skillDirectory("no-such-skill", false));
            assertTrue(failure.getMessage().contains("no skill named"), failure.getMessage());
        }
    }

    @Nested
    @DisplayName("install, list, check, remove")
    class ManagedSkills {

        @Test
        void installsTheSelfSkillIntoEveryDetectedAgent() throws IOException {
            skills().install(java.util.Optional.empty(), false, false);

            assertTrue(Files.isRegularFile(
                    AgentRegistry.CLAUDE_CODE.skillsDirectory()
                            .resolve(SelfSkill.NAME)
                            .resolve("SKILL.md")));
        }

        @Test
        void installsACatalogSkillByCopy() throws IOException {
            skills().install(java.util.Optional.of("cypher-basics"), false, false);

            Path installed = AgentRegistry.CLAUDE_CODE.skillsDirectory().resolve("cypher-basics");
            assertEquals(
                    "# Cypher \"basics\" for\nnew agents",
                    Files.readString(installed.resolve("SKILL.md"), StandardCharsets.UTF_8).strip());
        }

        @Test
        void reportsCheckAsCleanAfterAnInstall() throws IOException {
            var manager = skills();
            manager.install(java.util.Optional.empty(), false, false);

            assertEquals(0, manager.check(false));
        }

        @Test
        void reportsCheckAsDriftedAfterTheVersionChanges() throws IOException {
            var manager = skills();
            manager.install(java.util.Optional.empty(), false, false);

            var bumped = new Skills(
                    new SelfSkill("1.3.0"), catalog(), AgentRegistry.detectedAgents(), reporter());
            assertEquals(1, bumped.check(false));
            assertTrue(printed.toString().contains("drifted"));
        }

        @Test
        void installsAMultiFileCatalogSkillWhole() throws IOException {
            // The fake catalog now serves a references/ file alongside cypher-basics's SKILL.md;
            // both must arrive, and the catalog skill itself must not be reported as drift.
            var manager = skills();
            manager.install(java.util.Optional.of("cypher-basics"), false, false);

            Path installed =
                    AgentRegistry.CLAUDE_CODE.skillsDirectory().resolve("cypher-basics");
            assertTrue(Files.isRegularFile(installed.resolve("references/examples.md")));
            printed.reset();
            manager.check(false);
            assertFalse(
                    printed.toString().contains("cypher-basics"),
                    "a whole install is not drift: "
                            + printed.toString().replace('\n', ' '));
        }

        @Test
        void removingAnAbsentSkillIsQuiet() throws IOException {
            skills().remove(java.util.Optional.of("cypher-basics"), false);

            assertFalse(printed.toString().contains("removed"),
                    "nothing was installed, so nothing is reported as removed");
        }

        @Test
        void refusesToOperateWhenNoAgentIsKnown() {
            var noAgents = new Skills(
                    new SelfSkill("1.2.1"), catalog(), List.of(), reporter());

            var failure = assertThrows(IllegalStateException.class,
                    () -> noAgents.install(java.util.Optional.empty(), false, false));
            assertTrue(failure.getMessage().contains("--agent"), failure.getMessage());
        }

        @Test
        void listsAreHonestAboutHavingNoAgents() throws IOException {
            var noAgents = new Skills(
                    new SelfSkill("1.2.1"), catalog(), List.of(), reporter());

            noAgents.list(false);

            assertTrue(printed.toString().contains("No supported agent"), printed.toString());
        }

        @Test
        void removesTheSelfSkillWhenNamedExplicitly() throws IOException {
            skills().install(java.util.Optional.empty(), false, false);

            skills().remove(java.util.Optional.of("self"), false);

            assertFalse(Files.exists(
                    AgentRegistry.CLAUDE_CODE.skillsDirectory().resolve(SelfSkill.NAME)));
        }

        @Test
        void checkSurvivesAnUnreachableCatalogAndStillReportsSelfDrift() throws IOException {
            var manager = skills();
            manager.install(java.util.Optional.empty(), false, false);

            var cutOff = new Skills(
                    new SelfSkill("1.3.0"),
                    new Catalog("http://localhost:1/repos/neo4j-contrib/neo4j-skills",
                            cache, warnings::add),
                    AgentRegistry.detectedAgents(),
                    reporter());

            // A forced refresh against a dead port with no cache: the catalog degrades to
            // self-only with one announced warning, and the self-skill finding still surfaces.
            assertEquals(1, cutOff.check(true), "the self-skill finding survives");
            assertEquals(
                    1,
                    errored.toString().split("catalog is unavailable", -1).length - 1,
                    "the catalog outage is announced exactly once");
        }

        @Test
        void removesEveryCatalogSkillButPreservesSelf() throws IOException {
            var manager = skills();
            manager.install(java.util.Optional.empty(), true, false);

            manager.remove(java.util.Optional.empty(), true);

            assertFalse(Files.exists(
                    AgentRegistry.CLAUDE_CODE.skillsDirectory().resolve("cypher-basics")));
            assertTrue(Files.exists(
                    AgentRegistry.CLAUDE_CODE.skillsDirectory()
                            .resolve(SelfSkill.NAME)
                            .resolve("SKILL.md")),
                    "remove --all preserves the self-skill");
        }

        @Test
        void autoRefreshUpdatesAStaleBundle() throws IOException {
            new SelfSkill("1.0.0").installInto(AgentRegistry.CLAUDE_CODE);

            skills().autoRefresh();

            assertEquals(
                    java.util.Optional.of("1.2.1"),
                    new SelfSkill("1.2.1").installedVersion(AgentRegistry.CLAUDE_CODE));
        }
    }
}
