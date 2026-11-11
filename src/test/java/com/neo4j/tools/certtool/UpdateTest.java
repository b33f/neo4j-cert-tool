package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.output.FilePermissions;
import com.neo4j.tools.certtool.output.Reporter;
import com.neo4j.tools.certtool.update.Releases;
import com.neo4j.tools.certtool.update.Update;
import com.neo4j.tools.certtool.update.Version;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Exercises the update command against a local server that impersonates the GitHub release feed:
 * release documents, the jar asset and its SHA256SUMS.txt, all served from one {@code HttpServer}.
 */
class UpdateTest {

    private static final String REPO_PATH = "/repos/b33f/neo4j-cert-tool";
    private static final String OWNER = "b33f/neo4j-cert-tool";

    /** The latest stable release the fake feed offers. */
    private static final String LATEST_STABLE = "v1.3.0";

    /** A pre-release newer than the stable one, so --pre-releases changes the answer. */
    private static final String NEWER_PRE_RELEASE = "v1.4.0-rc1";

    private HttpServer server;
    private String apiBase;
    private String downloadPrefix;
    private final Map<String, byte[]> downloads = new HashMap<>();

    /** Request paths that answer 302, mapping to the Location the fake server should name. */
    private final Map<String, String> redirects = new HashMap<>();
    private final ByteArrayOutputStream printed = new ByteArrayOutputStream();

    /** The jar the "installed" tool is running from, replaced by the update under test. */
    @TempDir
    Path temp;

    private Path jar;

    @BeforeEach
    void startFakeGitHub() throws Exception {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/", this::serve);
        server.start();
        int port = server.getAddress().getPort();
        apiBase = "http://localhost:" + port + REPO_PATH;
        downloadPrefix = "http://localhost:" + port + "/files/" + OWNER + "/releases/download/";

        storeJar("v1.3.0", "the contents of the new jar");
        storeJar("v0.9.0", "an older jar, for downgrade testing");
        // SHA256SUMS.txt is rebuilt whenever a test tampers with a jar.
        rewriteSums("v1.3.0");
        rewriteSums("v0.9.0");

        jar = temp.resolve("neo4j-cert-tool.jar");
        Files.writeString(jar, "the currently running jar", StandardCharsets.UTF_8);
        if (FilePermissions.posixSupported()) {
            Files.setPosixFilePermissions(jar, PosixFilePermissions.fromString("rw-r--r--"));
        }
    }

    @AfterEach
    void stopFakeGitHub() {
        server.stop(0);
    }

    private void storeJar(String tag, String contents) {
        String jarName = jarAssetName(tag);
        downloads.put(tag + "/" + jarName, contents.getBytes(StandardCharsets.UTF_8));
    }

    private static String jarAssetName(String tag) {
        return "neo4j-cert-tool-" + tag.substring(1) + ".jar";
    }

    /** Rebuilds SHA256SUMS.txt from whatever bytes the jar asset currently holds. */
    private void rewriteSums(String tag) throws NoSuchAlgorithmException {
        String jarName = jarAssetName(tag);
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(downloads.get(tag + "/" + jarName));
        downloads.put(tag + "/SHA256SUMS.txt", (hex(digest) + "  " + jarName + "\n")
                .getBytes(StandardCharsets.UTF_8));
    }

    /** A canned response that overrides the fake server's usual behaviour for one path. */
    private record Answer(int status, String body, String location) {
        static Answer of(int status, String body) {
            return new Answer(status, body, null);
        }

        static Answer redirect(String location) {
            return new Answer(302, null, location);
        }
    }

    private final Map<String, Answer> answers = new HashMap<>();

    private void serve(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String relative = path.startsWith("/files/" + OWNER + "/releases/download/")
                ? path.substring(("/files/" + OWNER + "/releases/download/").length())
                : null;
        Answer answer = answers.get(path);
        if (answer != null) {
            if (answer.location() != null) {
                exchange.getResponseHeaders().set("Location", answer.location());
            }
            if (answer.body() == null) {
                exchange.sendResponseHeaders(answer.status(), -1);
            } else {
                byte[] body = answer.body().getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(answer.status(), body.length);
                try (var out = exchange.getResponseBody()) {
                    out.write(body);
                }
            }
            return;
        }
        if (relative != null && redirects.containsKey(relative)) {
            exchange.getResponseHeaders().set("Location", redirects.get(relative));
            exchange.sendResponseHeaders(302, -1);
            return;
        }
        byte[] body;
        if (path.equals(REPO_PATH + "/releases/latest")) {
            body = releaseDocument(LATEST_STABLE).getBytes(StandardCharsets.UTF_8);
        } else if (path.equals(REPO_PATH + "/releases")) {
            // Newest first, as GitHub lists them. The pre-release outranks the stable release,
            // so only --pre-releases may select it.
            body = ("[" + releaseDocument(NEWER_PRE_RELEASE) + ","
                            + releaseDocument(LATEST_STABLE) + ","
                            + releaseDocument("v1.2.1") + "]")
                    .getBytes(StandardCharsets.UTF_8);
        } else if (path.startsWith(REPO_PATH + "/releases/tags/")) {
            body = releaseDocument("v0.9.0").getBytes(StandardCharsets.UTF_8);
        } else if (path.startsWith("/files/" + OWNER + "/releases/download/")) {
            body = downloads.get(relative);
            if (body == null) {
                exchange.sendResponseHeaders(404, -1);
                return;
            }
        } else {
            exchange.sendResponseHeaders(404, -1);
            return;
        }
        exchange.sendResponseHeaders(200, body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
    }

    private String releaseDocument(String tag) {
        return releaseDocument(tag, false);
    }

    private String releaseDocument(String tag, boolean draft) {
        String version = tag.substring(1);
        String base = downloadPrefix + tag;
        return """
            {"tag_name": "%s", "draft": %s, "prerelease": false,
             "assets": [
               {"name": "neo4j-cert-tool-%s.jar", "browser_download_url": "%s/neo4j-cert-tool-%s.jar"},
               {"name": "neo4j-cert-tool-%s.zip", "browser_download_url": "%s/neo4j-cert-tool-%s.zip"},
               {"name": "SHA256SUMS.txt", "browser_download_url": "%s/SHA256SUMS.txt"}
             ]}
            """
                .formatted(
                        tag, draft, version, base, version, version, base, version, base);
    }

    private Reporter reporter() {
        return new Reporter(new PrintStream(printed), System.err, false);
    }

    private String baseUrl() {
        return "http://localhost:" + server.getAddress().getPort();
    }

    private Releases releases() {
        // The default allowlist names only GitHub's hosts; the loopback server needs itself on
        // it for a redirect between two paths on the fake feed to be followed.
        var allowed = java.util.Set.of(
                "api.github.com",
                "github.com",
                "objects.githubusercontent.com",
                "release-assets.githubusercontent.com",
                "localhost");
        return new Releases(apiBase, downloadPrefix, allowed);
    }

    private static String hex(byte[] digest) {
        StringBuilder text = new StringBuilder(digest.length * 2);
        for (byte b : digest) {
            text.append("%02x".formatted(b));
        }
        return text.toString();
    }

    @Nested
    @DisplayName("version ordering")
    class VersionOrdering {

        @Test
        void ordersByComponents() {
            assertTrue(Version.parse("v1.3.0").orElseThrow()
                    .compareTo(Version.parse("v1.2.9").orElseThrow()) > 0);
            assertTrue(Version.parse("v2.0.0").orElseThrow()
                    .compareTo(Version.parse("v1.9.9").orElseThrow()) > 0);
        }

        @Test
        void sortsAReleaseCandidateBelowItsRelease() {
            assertTrue(Version.parse("v1.3.0-rc1").orElseThrow()
                    .compareTo(Version.parse("v1.3.0").orElseThrow()) < 0);
        }

        @Test
        void countsReleaseCandidatesNumerically() {
            assertTrue(Version.parse("v1.3.0-rc10").orElseThrow()
                    .compareTo(Version.parse("v1.3.0-rc2").orElseThrow()) > 0);
        }

        @Test
        void treatsIdenticalSuffixedVersionsAsEqual() {
            assertEquals(
                    0,
                    Version.parse("v1.3.0-rc1").orElseThrow()
                            .compareTo(Version.parse("1.3.0-rc1").orElseThrow()));
        }

        @Test
        void sortsTextSuffixesLexically() {
            assertTrue(Version.parse("v1.3.0-alpha").orElseThrow()
                    .compareTo(Version.parse("v1.3.0-beta").orElseThrow()) < 0);
        }

        @Test
        void acceptsTheVersionTheJarReportsItself() {
            // The jar manifest prints "1.2.1", releases print "v1.2.1": both must parse.
            assertEquals(Version.parse("v1.2.1"), Version.parse("1.2.1"));
        }

        @Test
        void rejectsTagsThisProjectWouldNotPublish() {
            assertTrue(Version.parse("not-a-version").isEmpty());
            assertTrue(Version.parse("(development build)").isEmpty());
        }
    }

    @Nested
    @DisplayName("update check")
    class Check {

        @Test
        void reportsANewerStableRelease() throws Exception {
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            assertEquals(Update.Outcome.NEWER_AVAILABLE, update.check());
            assertTrue(printed.toString().contains(LATEST_STABLE));
        }

        @Test
        void reportsUpToDateAtTheLatestStable() throws Exception {
            var update = new Update(jar, "1.3.0", releases(), reporter(), false, null);

            assertEquals(Update.Outcome.UP_TO_DATE, update.check());
            assertTrue(printed.toString().contains("Up to date"));
        }

        @Test
        void considersAPreReleaseOnlyWhenAsked() throws Exception {
            var stable = new Update(jar, "1.2.1", releases(), reporter(), false, null);
            assertEquals(Update.Outcome.NEWER_AVAILABLE, stable.check());
            assertTrue(printed.toString().contains(LATEST_STABLE));
            assertFalse(printed.toString().contains(NEWER_PRE_RELEASE));

            printed.reset();
            var withPre = new Update(jar, "1.2.1", releases(), reporter(), true, null);
            assertEquals(Update.Outcome.NEWER_AVAILABLE, withPre.check());
            assertTrue(printed.toString().contains(NEWER_PRE_RELEASE));
        }

        @Test
        void reportsTheLatestEvenForADevelopmentBuild() throws Exception {
            var update = new Update(jar, "(development build)", releases(), reporter(), false, null);

            // No comparison is possible, so it cannot claim an update is needed.
            assertEquals(Update.Outcome.UP_TO_DATE, update.check());
            assertTrue(printed.toString().contains(LATEST_STABLE));
        }
    }

    @Nested
    @DisplayName("update install")
    class Install {

        @Test
        void swapsTheJarForTheNewerRelease() throws Exception {
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            assertEquals(Update.Outcome.UPDATED, update.install());

            assertEquals(
                    "the contents of the new jar", Files.readString(jar, StandardCharsets.UTF_8));
            assertFalse(
                    Files.exists(jar.resolveSibling("neo4j-cert-tool.jar.download")),
                    "the download staging file is cleaned up");
        }

        @Test
        void keepsTheOldPermissions() throws Exception {
            if (!FilePermissions.posixSupported()) {
                return; // nothing to assert on a file system without mode bits
            }
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            update.install();

            assertEquals(
                    PosixFilePermissions.fromString("rw-r--r--"),
                    Files.getPosixFilePermissions(jar));
        }

        @Test
        void refusesToSwapADevelopmentBuild() {
            var update = new Update(null, "1.2.1", releases(), reporter(), false, null);

            assertThrows(IllegalStateException.class, update::install);
        }

        @Test
        void leavesTheRunningJarUntouchedOnAChecksumMismatch() throws Exception {
            String tampered = "deadbeef".repeat(8) + "  " + jarAssetName(LATEST_STABLE) + "\n";
            downloads.put(LATEST_STABLE + "/SHA256SUMS.txt", tampered.getBytes(StandardCharsets.UTF_8));
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            assertThrows(IOException.class, update::install);

            assertEquals(
                    "the currently running jar",
                    Files.readString(jar, StandardCharsets.UTF_8),
                    "a bad checksum must never touch the running jar");
            assertFalse(Files.exists(jar.resolveSibling("neo4j-cert-tool.jar.download")));
        }

        @Test
        void doesNothingWhenAlreadyUpToDate() throws Exception {
            var update = new Update(jar, "1.3.0", releases(), reporter(), false, null);

            assertEquals(Update.Outcome.UP_TO_DATE, update.install());

            assertEquals(
                    "the currently running jar", Files.readString(jar, StandardCharsets.UTF_8));
        }

        @Test
        void downgradesOnlyWhenPinned() throws Exception {
            var pinned = new Update(jar, "1.2.1", releases(), reporter(), false, "v0.9.0");

            assertEquals(Update.Outcome.UPDATED, pinned.install());
            assertEquals(
                    "an older jar, for downgrade testing",
                    Files.readString(jar, StandardCharsets.UTF_8));
        }

        @Test
        void followsARedirectOnlyToAnAllowlistedHost() throws Exception {
            // The real feed redirects release downloads to GitHub's asset storage; a redirect
            // that stays on an allowed host must be followed.
            redirects.put("v1.3.0/neo4j-cert-tool-1.3.0.jar", baseUrl() + "/elsewhere");
            server.createContext("/elsewhere", exchange -> {
                byte[] body = "redirected jar".getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(200, body.length);
                try (var out = exchange.getResponseBody()) {
                    out.write(body);
                }
            });
            // The checksum manifest describes whatever the download resolves to, here the
            // bytes the redirect serves.
            storeJar(LATEST_STABLE, "redirected jar");
            rewriteSums(LATEST_STABLE);
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            assertEquals(Update.Outcome.UPDATED, update.install());
            assertEquals("redirected jar", Files.readString(jar, StandardCharsets.UTF_8));
        }

        @Test
        void refusesARedirectOutsideTheAllowedHosts() throws Exception {
            // An on-path attacker or a compromised feed must not be able to send the download
            // somewhere else by naming a different host in a Location header.
            redirects.put(
                    "v1.3.0/neo4j-cert-tool-1.3.0.jar", "http://attacker.example/jar");
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            assertThrows(IOException.class, update::install);
            assertEquals(
                    "the currently running jar",
                    Files.readString(jar, StandardCharsets.UTF_8),
                    "a refused redirect must leave the running jar untouched");
        }

        @Test
        void refusesARedirectThatChangesTheScheme() throws Exception {
            // The fake feed speaks HTTP because a loopback server cannot cheaply present a
            // certificate, so the downgrade runs the other way: the rule being tested is that no
            // hop may change the scheme at all, in either direction.
            redirects.put("v1.3.0/neo4j-cert-tool-1.3.0.jar", "https://localhost/never-reached");
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            assertThrows(IOException.class, update::install);
            assertEquals("the currently running jar", Files.readString(jar, StandardCharsets.UTF_8));
        }

        @Test
        void givesUpAfterTooManyRedirects() throws Exception {
            // A redirect loop must end in an error, not a hang: the jar asset redirects to itself.
            String assetPath = "/files/" + OWNER + "/releases/download/"
                    + LATEST_STABLE + "/" + jarAssetName(LATEST_STABLE);
            answers.put(assetPath, Answer.redirect(downloadPrefix + LATEST_STABLE + "/"
                    + jarAssetName(LATEST_STABLE)));
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            var failure = assertThrows(IOException.class, update::install);
            assertTrue(failure.getMessage().contains("redirects"), failure.getMessage());
            assertEquals("the currently running jar", Files.readString(jar, StandardCharsets.UTF_8));
        }

        @Test
        void installsAPreReleaseWhenAsked() throws Exception {
            storeJar(NEWER_PRE_RELEASE, "the pre-release jar");
            rewriteSums(NEWER_PRE_RELEASE);
            var update = new Update(jar, "1.2.1", releases(), reporter(), true, null);

            assertEquals(Update.Outcome.UPDATED, update.install());
            assertEquals("the pre-release jar", Files.readString(jar, StandardCharsets.UTF_8));
        }
    }

    /** The guard rails around what the release feed is believed to say. */
    @Nested
    @DisplayName("release feed hardening")
    class FeedHardening {

        private String assetPath() {
            return "/files/" + OWNER + "/releases/download/"
                    + LATEST_STABLE + "/" + jarAssetName(LATEST_STABLE);
        }

        @Test
        void rejectsADraftRelease() throws Exception {
            answers.put(REPO_PATH + "/releases/latest",
                    Answer.of(200, releaseDocument(LATEST_STABLE, true)));
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            var failure = assertThrows(IOException.class, update::install);
            assertTrue(failure.getMessage().contains("draft"), failure.getMessage());
            assertEquals("the currently running jar", Files.readString(jar, StandardCharsets.UTF_8));
        }

        @Test
        void rejectsATagThatIsNotAVersionThisToolWouldPublish() {
            answers.put(REPO_PATH + "/releases/latest",
                    Answer.of(200, releaseDocument("not-a-version")));
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            var failure = assertThrows(IOException.class, update::install);
            assertTrue(failure.getMessage().contains("not a version"), failure.getMessage());
        }

        @Test
        void rejectsAReleaseWithoutTheJarAsset() {
            answers.put(REPO_PATH + "/releases/latest", Answer.of(200, """
                {"tag_name": "%s", "draft": false, "prerelease": false,
                 "assets": [
                   {"name": "neo4j-cert-tool-1.3.0.zip", "browser_download_url": "%s/zip"},
                   {"name": "SHA256SUMS.txt", "browser_download_url": "%s/SHA256SUMS.txt"}
                 ]}
                """
                    .formatted(LATEST_STABLE, downloadPrefix + LATEST_STABLE,
                            downloadPrefix + LATEST_STABLE)));
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            var failure = assertThrows(IOException.class, update::install);
            assertTrue(failure.getMessage().contains("no " + jarAssetName(LATEST_STABLE)),
                    failure.getMessage());
        }

        @Test
        void refusesADownloadUrlOutsideThisRepository() throws Exception {
            // The feed names a download URL on some other host: it must be refused before any
            // connection is made, however trustworthy the rest of the document looks.
            answers.put(REPO_PATH + "/releases/latest", Answer.of(200, """
                {"tag_name": "%s", "draft": false, "prerelease": false,
                 "assets": [
                   {"name": "%s", "browser_download_url": "https://evil.example/x.jar"},
                   {"name": "SHA256SUMS.txt", "browser_download_url": "%sSHA256SUMS.txt"}
                 ]}
                """
                    .formatted(
                            LATEST_STABLE,
                            jarAssetName(LATEST_STABLE),
                            downloadPrefix + LATEST_STABLE + "/")));
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            var failure = assertThrows(IOException.class, update::install);
            assertTrue(failure.getMessage().contains("unexpected download URL"),
                    failure.getMessage());
            assertEquals("the currently running jar", Files.readString(jar, StandardCharsets.UTF_8));
        }

        @Test
        void reportsWhenNothingExistsAtThePinnedTag() {
            answers.put(REPO_PATH + "/releases/tags/v9.9.9", Answer.of(404, null));
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, "v9.9.9");

            var failure = assertThrows(IOException.class, update::install);
            assertTrue(failure.getMessage().contains("no such release or tag"),
                    failure.getMessage());
        }

        @Test
        void reportsAServerErrorInsteadOfGuessing() {
            answers.put(REPO_PATH + "/releases/latest", Answer.of(500, "boom"));
            var update = new Update(jar, "1.2.1", releases(), reporter(), false, null);

            var failure = assertThrows(IOException.class, update::install);
            assertTrue(failure.getMessage().contains("HTTP 500"), failure.getMessage());
        }
    }
}
