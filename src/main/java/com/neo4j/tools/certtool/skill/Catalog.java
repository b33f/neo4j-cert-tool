package com.neo4j.tools.certtool.skill;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The curated catalog of installable skills, fetched from a GitHub repository.
 *
 * <p>A catalog skill is any directory in the repository holding a {@code SKILL.md}. The catalog is
 * cached under the user's cache directory with a twenty-four hour lifetime: installs, listings and
 * checks auto-refresh a stale cache, and every entry falls back to the cached copy when the
 * network fails, with a warning on standard error.
 */
public final class Catalog {

    /** The repository the curated skills are fetched from. */
    static final String CATALOG_REPO = "neo4j-contrib/neo4j-skills";

    private static final Duration TTL = Duration.ofHours(24);
    private static final String FETCHED_AT_FILE = ".fetched-at";

    private final String apiBase;
    private final Path cacheRoot;
    private final HttpClient client;
    private final java.util.function.Consumer<String> warn;

    /** @param warn receives the stale-cache fallback warning; standard error in production */
    public Catalog(Path cacheRoot, java.util.function.Consumer<String> warn) {
        this("https://api.github.com/repos/" + CATALOG_REPO, cacheRoot, warn);
    }

    /** The same, with an explicit API root so tests can serve a fake catalog. */
    public Catalog(String apiBase, Path cacheRoot, java.util.function.Consumer<String> warn) {
        this.apiBase = apiBase;
        this.cacheRoot = cacheRoot;
        this.warn = warn;
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .build();
    }

    /** Every skill name the catalog currently offers, from the network or the cache. */
    public List<String> names(boolean forceRefresh) throws IOException {
        refreshIfStale(forceRefresh);
        return readCachedNames();
    }

    /** One skill's files, as absolute paths under the local cache. */
    public Path skillDirectory(String name, boolean forceRefresh) throws IOException {
        refreshIfStale(forceRefresh);
        Path directory = cacheRoot.resolve(name);
        if (!Files.isRegularFile(directory.resolve("SKILL.md"))) {
            throw new IOException(
                    "The catalog holds no skill named '" + name + "'. Run 'skill list' to see "
                            + "what is available.");
        }
        return directory;
    }

    /**
     * Fetches the catalog when the cache is older than its TTL, or when {@code force} is set.
     *
     * @throws IOException when there is no cache to fall back to and the fetch fails
     */
    public void refreshIfStale(boolean force) throws IOException {
        Path stamp = cacheRoot.resolve(FETCHED_AT_FILE);
        if (!force && Files.isRegularFile(stamp)) {
            try {
                Instant fetched = Instant.parse(Files.readString(stamp).strip());
                if (Instant.now().isBefore(fetched.plus(TTL))) {
                    return;
                }
            } catch (DateTimeParseException unreadable) {
                // Fall through and refresh.
            }
        }
        try {
            fetch();
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            if (!Files.isDirectory(cacheRoot) || readCachedNames().isEmpty()) {
                throw new IOException(
                        "Cannot reach the skill catalog (" + CATALOG_REPO + ") and nothing is "
                                + "cached: " + e.getMessage(),
                        e);
            }
            warn.accept(
                    "Cannot reach the skill catalog ("
                            + CATALOG_REPO
                            + "); using the cached copy from "
                            + cacheRoot);
        }
    }

    /** Downloads every skill directory in the repository into the cache. */
    private void fetch() throws IOException, InterruptedException {
        // One tree call lists everything; the contents calls then fetch each file base64-encoded.
        HttpResponse<String> tree = send(apiBase + "/git/trees/HEAD?recursive=1");
        List<String> skillFiles = skillBlobs(tree.body());
        if (skillFiles.isEmpty()) {
            throw new IOException("The catalog repository lists no skills");
        }

        Files.createDirectories(cacheRoot);
        for (String path : skillFiles) {
            HttpResponse<String> file = send(apiBase + "/contents/" + path);
            String content = jsonValue(file.body(), "content");
            if (content == null) {
                throw new IOException("The catalog file " + path + " came back without content");
            }
            byte[] bytes = Base64.getMimeDecoder().decode(content);
            Path target = cacheRoot.resolve(path.replace('/', java.io.File.separatorChar));
            Files.createDirectories(target.getParent());
            Files.write(target, bytes);
        }
        Files.writeString(cacheRoot.resolve(FETCHED_AT_FILE), Instant.now().toString());
    }

    /**
     * Every blob path in the tree that belongs to a skill: a skill is any directory holding a
     * {@code SKILL.md}, and everything under that directory is part of the skill — reference
     * files included, so a multi-file bundle installs whole.
     */
    private static List<String> skillBlobs(String treeJson) {
        // GitHub tree entries pair a path with a type in a fixed order; walk the two sequences
        // in step, the same way release assets pair name with download URL.
        Matcher paths = Pattern.compile("\"path\"\\s*:\\s*\"([^\"]+)\"").matcher(treeJson);
        Matcher types = Pattern.compile("\"type\"\\s*:\\s*\"([^\"]+)\"").matcher(treeJson);
        List<String> allPaths = new ArrayList<>();
        List<String> allTypes = new ArrayList<>();
        while (paths.find() && types.find()) {
            allPaths.add(paths.group(1));
            allTypes.add(types.group(1));
        }
        java.util.Set<String> skillRoots = new java.util.LinkedHashSet<>();
        for (int i = 0; i < allPaths.size(); i++) {
            if (isBlob(allTypes, i) && allPaths.get(i).endsWith("/SKILL.md")) {
                skillRoots.add(allPaths.get(i).substring(0, allPaths.get(i).length() - "/SKILL.md".length()));
            }
        }
        List<String> blobs = new ArrayList<>();
        for (int i = 0; i < allPaths.size(); i++) {
            if (!isBlob(allTypes, i)) {
                continue;
            }
            for (String root : skillRoots) {
                if (allPaths.get(i).startsWith(root + "/")) {
                    blobs.add(allPaths.get(i));
                    break;
                }
            }
        }
        return blobs;
    }

    private static boolean isBlob(List<String> types, int index) {
        return index < types.size() && "blob".equals(types.get(index));
    }

    private List<String> readCachedNames() throws IOException {
        List<String> names = new ArrayList<>();
        if (!Files.isDirectory(cacheRoot)) {
            return names;
        }
        try (var paths = Files.list(cacheRoot)) {
            // Sorted, so listings are reproducible across machines and file systems.
            for (Path directory : paths.filter(Files::isDirectory).sorted().toList()) {
                if (Files.isRegularFile(directory.resolve("SKILL.md"))) {
                    names.add(directory.getFileName().toString());
                }
            }
        }
        return names;
    }

    private HttpResponse<String> send(String url) throws IOException, InterruptedException {
        HttpRequest request = request(url);
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException(url + " answered with HTTP " + response.statusCode());
        }
        return response;
    }

    private static HttpRequest request(String url) {
        return HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("User-Agent", "neo4j-cert-tool")
                .header("Accept", "application/vnd.github+json")
                .GET()
                .build();
    }

    /**
     * Reads a top-level JSON string value by key, unescaping it.
     *
     * <p>A regex cannot be used here: catalog SKILL.md files are kilobytes long and the
     * escape-aware alternation a JSON string needs overflows the stack inside the JDK's regex
     * engine. A linear scan does not.
     */
    private static String jsonValue(String json, String key) {
        int keyAt = json.indexOf("\"" + key + "\"");
        if (keyAt < 0) {
            return null;
        }
        int colon = json.indexOf(':', keyAt + key.length() + 2);
        int quote = json.indexOf('"', colon + 1);
        if (quote < 0) {
            return null;
        }
        StringBuilder value = new StringBuilder();
        for (int i = quote + 1; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '"') {
                return value.toString();
            }
            if (c == '\\') {
                char escaped = json.charAt(++i);
                value.append(switch (escaped) {
                    case 'n' -> '\n';
                    case 't' -> '\t';
                    case 'r' -> '\r';
                    default -> escaped; // \" \\ \/ — and base64 needs no other unescaping
                });
                continue;
            }
            value.append(c);
        }
        return null; // unterminated: treat as absent
    }
    /** The user's cache directory: macOS Library/Caches, XDG on Linux, LOCALAPPDATA on Windows. */
    public static Path userCacheDirectory() {
        return userCacheRoot().resolve("skill-catalog");
    }

    /** The root of everything this tool caches between runs, under the platform's cache home. */
    public static Path userCacheRoot() {
        String home = System.getProperty("user.home");
        String os = System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT);
        if (os.contains("mac")) {
            return Path.of(home, "Library", "Caches", "neo4j-cert-tool");
        }
        if (os.contains("windows")) {
            String localAppData = System.getenv("LOCALAPPDATA");
            String base = localAppData != null && !localAppData.isBlank()
                    ? localAppData
                    : Path.of(home, "AppData", "Local").toString();
            return Path.of(base, "neo4j-cert-tool");
        }
        String xdg = System.getenv("XDG_CACHE_HOME");
        String base = xdg != null && !xdg.isBlank() ? xdg : Path.of(home, ".cache").toString();
        return Path.of(base, "neo4j-cert-tool");
    }

    /** Standard output goes elsewhere, so warnings surface here. */
    public static java.util.function.Consumer<String> standardErrors() {
        return message -> System.err.println("Warning: " + message);
    }
}
