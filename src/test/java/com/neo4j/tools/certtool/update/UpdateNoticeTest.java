package com.neo4j.tools.certtool.update;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.skill.Catalog;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The once-a-day update-availability notice: when it is due, what it announces, and how quietly it
 * fails.
 */
class UpdateNoticeTest {

    private static final String REPO_PATH = "/repos/neo4j-labs/neo4j-cert-tool";

    @TempDir
    Path temp;

    private HttpServer server;
    private String apiBase;
    private String downloadPrefix;
    private Path stampFile;

    @BeforeEach
    void startFakeGitHub() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext(REPO_PATH, this::serve);
        server.start();
        int port = server.getAddress().getPort();
        apiBase = "http://localhost:" + port + REPO_PATH;
        downloadPrefix = "http://localhost:" + port
                + "/files/neo4j-labs/neo4j-cert-tool/releases/download/";
        stampFile = temp.resolve("update-check");
    }

    @AfterEach
    void stopFakeGitHub() {
        server.stop(0);
    }

    private void serve(com.sun.net.httpserver.HttpExchange exchange) throws IOException {
        byte[] body = """
            {"tag_name": "v1.3.0", "draft": false, "prerelease": false,
             "assets": [
               {"name": "neo4j-cert-tool-1.3.0.jar", "browser_download_url": "%sneo4j-cert-tool-1.3.0.jar"},
               {"name": "SHA256SUMS.txt", "browser_download_url": "%sSHA256SUMS.txt"}
             ]}
            """
                .formatted(downloadPrefix + "v1.3.0/", downloadPrefix + "v1.3.0/")
                .getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private Releases releases() {
        return new Releases(apiBase, downloadPrefix);
    }

    private UpdateNotice notice(String runningVersion) {
        return new UpdateNotice(stampFile, releases(), runningVersion);
    }

    @Nested
    @DisplayName("when the check is due")
    class Due {

        @Test
        void isFirstRunOfTheDay() {
            assertTrue(notice("1.2.1").due(), "no stamp yet: the check is due");
        }

        @Test
        void isNotDueAgainWithinTheDay() throws IOException {
            UpdateNotice checked = notice("1.2.1");
            checked.check();

            assertFalse(checked.due(), "a stamp from moments ago holds the day");
        }

        @Test
        void comesDueAgainAfterTwentyFourHours() throws IOException {
            notice("1.2.1").check();
            Files.writeString(
                    stampFile,
                    Instant.now().minus(Duration.ofHours(25)).toString(),
                    StandardCharsets.UTF_8);

            assertTrue(notice("1.2.1").due(), "yesterday's stamp is stale");
        }

        @Test
        void comesDueWhenTheStampIsUnreadable() throws IOException {
            Files.writeString(stampFile, "garbage", StandardCharsets.UTF_8);

            assertTrue(notice("1.2.1").due(), "a corrupt stamp must not silence the check");
        }

        @Test
        void neverRunsForADevelopmentBuild() {
            assertFalse(
                    notice("(development build)").due(),
                    "a development build has nothing to compare against");
        }
    }

    @Nested
    @DisplayName("what the check announces")
    class Announcement {

        @Test
        void announcesANewerReleaseWithTheRemedy() {
            Optional<String> announcement = notice("1.2.1").check();

            assertTrue(announcement.isPresent());
            assertTrue(announcement.get().contains("v1.3.0"), announcement.get());
            assertTrue(announcement.get().contains("1.2.1"), announcement.get());
            assertTrue(announcement.get().contains("update"), announcement.get());
        }

        @Test
        void staysQuietWhenCurrent() {
            assertTrue(notice("1.3.0").check().isEmpty(), "no announcement when up to date");
        }

        @Test
        void checksOnlyOncePerDay() {
            notice("1.2.1").check();
            // The second look on the same day is not due, so no announcement is made twice.
            assertTrue(notice("1.2.1").check().isEmpty());
        }

        @Test
        void isSilentWhenTheNetworkIsDead() {
            var unreachable = new UpdateNotice(
                    stampFile,
                    new Releases("http://localhost:1" + REPO_PATH, downloadPrefix),
                    "1.2.1");

            assertTrue(unreachable.check().isEmpty(), "a failed courtesy is silent");
        }

        @Test
        void spendsTheDaysAttemptEvenWhenItFails() throws IOException {
            var unreachable = new UpdateNotice(
                    stampFile,
                    new Releases("http://localhost:1" + REPO_PATH, downloadPrefix),
                    "1.2.1");
            unreachable.check();

            assertTrue(Files.isRegularFile(stampFile),
                    "the stamp is written before the attempt, bounding the cost to once a day");
        }
    }

    @Nested
    @DisplayName("switching the check off")
    class SwitchingItOff {

        @Test
        void theEnvironmentVariableDisablesIt() {
            assertTrue(UpdateNotice.disabledByEnvironment("false"));
            assertTrue(UpdateNotice.disabledByEnvironment("FALSE"));
            assertTrue(UpdateNotice.disabledByEnvironment(" false "));
            assertFalse(UpdateNotice.disabledByEnvironment("true"));
            assertFalse(UpdateNotice.disabledByEnvironment(null));
        }

        @Test
        void theCacheRootIsWhereTheStampLives() {
            // The stamp sits under the same root as the skill catalog, so a user clearing the
            // tool's cache clears both.
            assertTrue(Catalog.userCacheRoot().endsWith("neo4j-cert-tool"));
        }
    }
}
