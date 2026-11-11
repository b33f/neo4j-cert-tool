package com.neo4j.tools.certtool.update;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads this project's releases from the GitHub API.
 *
 * <p>Uses only the JDK's HTTP client, keeping the shipped jar dependency-free. The API responses
 * are treated as untrusted input: a tag is never used before it parses as a version this tool
 * would publish, and a download URL is only followed when it points at this repository's release
 * assets on github.com.
 */
public final class Releases {

    /** One GitHub release, narrowed to the assets this tool updates itself from. */
    public record Release(String tag, String jarName, String jarUrl, String sha256SumsUrl) {}

    private static final String JAR_ASSET_PREFIX = "neo4j-cert-tool-";
    private static final String JAR_ASSET_SUFFIX = ".jar";
    private static final String SHA256SUMS_ASSET = "SHA256SUMS.txt";

    private static final Pattern TAG_NAME =
            Pattern.compile("\"tag_name\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern DRAFT_FLAG = Pattern.compile("\"draft\"\\s*:\\s*(true|false)");
    private static final Pattern ASSET_NAME = Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");
    private static final Pattern ASSET_URL =
            Pattern.compile("\"browser_download_url\"\\s*:\\s*\"([^\"]+)\"");

    /** The only hosts any connection, including a redirect, is allowed to be made to. */
    private static final java.util.Set<String> DEFAULT_ALLOWED_HOSTS = java.util.Set.of(
            "api.github.com",
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com");

    /** Redirects are followed by hand so every hop can be checked against the allowlist. */
    private static final int MAX_REDIRECTS = 5;

    private final String apiBase;
    private final String downloadUrlPrefix;
    private final java.util.Set<String> allowedHosts;
    private final HttpClient client;

    /**
     * @param apiBase the API root, {@code https://api.github.com/repos/OWNER/REPO}
     * @param downloadUrlPrefix only asset URLs starting with this are followed, normally
     *     {@code https://github.com/OWNER/REPO/releases/download/}; the test suite points it at a
     *     local server
     */
    public Releases(String apiBase, String downloadUrlPrefix) {
        this(apiBase, downloadUrlPrefix, DEFAULT_ALLOWED_HOSTS);
    }

    /** The same, with an explicit host allowlist — the test suite runs against localhost. */
    public Releases(String apiBase, String downloadUrlPrefix, java.util.Set<String> allowedHosts) {
        this.apiBase = apiBase;
        this.downloadUrlPrefix = downloadUrlPrefix;
        this.allowedHosts = allowedHosts;
        this.client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(15))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    /** The newest release to move to: the latest stable one, or the greatest version overall. */
    public Release latest(boolean includePreReleases) throws IOException {
        if (!includePreReleases) {
            // The endpoint itself excludes drafts and prereleases, so what comes back is stable.
            return readRelease(get(apiBase + "/releases/latest"));
        }
        return readReleases(get(apiBase + "/releases?per_page=50")).stream()
                .max((a, b) -> versionOf(a).compareTo(versionOf(b)))
                .orElseThrow(() -> new IOException("No releases published yet"));
    }

    /** The release for a named tag, used by the {@code --version} pin. */
    public Release byTag(String tag) throws IOException {
        String encoded = URLEncoder.encode(tag, StandardCharsets.UTF_8);
        return readRelease(get(apiBase + "/releases/tags/" + encoded));
    }

    /** Downloads a small asset in full, such as the checksum file. */
    public String downloadText(String url) throws IOException {
        try {
            HttpResponse<byte[]> response = sendAllowlisted(
                    request(url), HttpResponse.BodyHandlers.ofByteArray());
            return new String(response.body(), StandardCharsets.UTF_8);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while downloading " + url, e);
        }
    }

    /** Opens a larger asset for streaming download, such as the jar itself. */
    public java.io.InputStream downloadStream(String url) throws IOException {
        try {
            HttpResponse<java.io.InputStream> response =
                    sendAllowlisted(request(url), HttpResponse.BodyHandlers.ofInputStream());
            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while downloading " + url, e);
        }
    }

    // --- response parsing -------------------------------------------------------------------

    private List<Release> readReleases(String json) throws IOException {
        // Split the document into individual release objects: the entries of the top-level array.
        List<Release> releases = new ArrayList<>();
        int depth = 0;
        int start = -1;
        boolean inString = false;
        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++; // skip the escaped character
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '[' || c == '{') {
                if (depth == 1 && c == '{') {
                    start = i; // an object directly inside the top-level array
                }
                depth++;
            } else if (c == ']' || c == '}') {
                depth--;
                if (depth == 1 && start >= 0) {
                    releases.add(readRelease(json.substring(start, i + 1)));
                    start = -1;
                }
            }
        }
        return releases;
    }

    private Release readRelease(String json) throws IOException {
        String tag = match(TAG_NAME, json, "tag_name");
        if (match(DRAFT_FLAG, json, "draft").equals("true")) {
            throw new IOException("The release at " + tag + " is a draft, not a published one");
        }
        Version version = Version.parse(tag)
                .orElseThrow(() -> new IOException(
                        "The tag '" + tag + "' is not a version this tool would publish"));

        String assets = assetsArray(json);
        String jarName = JAR_ASSET_PREFIX + version + JAR_ASSET_SUFFIX;
        String jarUrl = null;
        String sha256Url = null;
        Matcher names = ASSET_NAME.matcher(assets);
        Matcher urls = ASSET_URL.matcher(assets);
        // GitHub emits each asset's name before its browser_download_url, so the two matcher
        // sequences advance in step.
        while (names.find() && urls.find()) {
            if (names.group(1).equals(jarName)) {
                jarUrl = urls.group(1);
            } else if (names.group(1).equals(SHA256SUMS_ASSET)) {
                sha256Url = urls.group(1);
            }
        }
        if (jarUrl == null || sha256Url == null) {
            throw new IOException(
                    "The release at " + tag + " has no " + jarName + " and " + SHA256SUMS_ASSET
                            + " pair to download");
        }
        jarUrl = requireOwnReleaseAsset(jarUrl, tag);
        sha256Url = requireOwnReleaseAsset(sha256Url, tag);
        return new Release(tag, jarName, jarUrl, sha256Url);
    }

    /** Isolates the {@code assets} array so release-level fields cannot pose as asset fields. */
    private static String assetsArray(String json) throws IOException {
        int marker = json.indexOf("\"assets\"");
        if (marker < 0) {
            throw new IOException("A release carried no assets");
        }
        int open = json.indexOf('[', marker);
        if (open < 0) {
            throw new IOException("A release carried a malformed assets array");
        }
        int depth = 0;
        boolean inString = false;
        for (int i = open; i < json.length(); i++) {
            char c = json.charAt(i);
            if (inString) {
                if (c == '\\') {
                    i++;
                } else if (c == '"') {
                    inString = false;
                }
                continue;
            }
            if (c == '"') {
                inString = true;
            } else if (c == '[') {
                depth++;
            } else if (c == ']') {
                depth--;
                if (depth == 0) {
                    return json.substring(open, i + 1);
                }
            }
        }
        throw new IOException("A release carried a malformed assets array");
    }

    /** A download URL is only followed when it points at this repository's release assets. */
    private String requireOwnReleaseAsset(String url, String tag) throws IOException {
        if (!url.startsWith(downloadUrlPrefix)) {
            throw new IOException(
                    "The release at " + tag + " offers an unexpected download URL: " + url);
        }
        return url;
    }

    private static String match(Pattern pattern, String text, String what) throws IOException {
        Matcher matcher = pattern.matcher(text);
        if (!matcher.find()) {
            throw new IOException("A release response carried no " + what);
        }
        return matcher.group(1);
    }

    private Version versionOf(Release release) {
        return Version.parse(release.tag()).orElse(Version.parse("v0.0.0").orElseThrow());
    }

    // --- HTTP --------------------------------------------------------------------------------

    private HttpRequest request(String url) {
        return HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(60))
                .header("User-Agent", "neo4j-cert-tool/" + currentVersionForUserAgent())
                .header("Accept", "application/vnd.github+json")
                .GET()
                .build();
    }

    private static String currentVersionForUserAgent() {
        String version = Update.class.getPackage().getImplementationVersion();
        return version != null ? version : "development";
    }

    private String get(String url) throws IOException {
        try {
            HttpResponse<String> response =
                    sendAllowlisted(request(url), HttpResponse.BodyHandlers.ofString());
            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while contacting " + url, e);
        }
    }

    /**
     * Sends the request, following redirects by hand so that every hop is checked against the
     * host allowlist before a connection is opened to it.
     *
     * <p>The JDK's own redirect following would connect to whatever the server names in
     * {@code Location}; handing a redirect to an uninvolved host is exactly the substitution an
     * update channel must not permit.
     */
    private <T> HttpResponse<T> sendAllowlisted(
            HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            HttpResponse<T> response = client.send(request, handler);
            int status = response.statusCode();
            if (status == 301 || status == 302 || status == 307 || status == 308) {
                String location = response.headers().firstValue("Location").orElse(null);
                if (location == null) {
                    throw new IOException(request.uri() + " redirected without a Location header");
                }
                URI target = request.uri().resolve(location);
                requireAllowlistedHost(target, request.uri().getScheme());
                request = rebuildRequest(request, target);
                continue;
            }
            requireOkay(request.uri().toString(), status);
            return response;
        }
        throw new IOException("More than " + MAX_REDIRECTS + " redirects following " + request.uri());
    }

    /**
     * A redirect may only land on an allowlisted host, and never downgrade the scheme: a
     * redirect from an HTTPS connection to plain HTTP would hand the traffic to whoever can
     * intercept it.
     */
    private void requireAllowlistedHost(URI target, String schemeSoFar) throws IOException {
        if (!schemeSoFar.equals(target.getScheme())) {
            throw new IOException(
                    "A redirect changed the scheme from " + schemeSoFar + " to "
                            + target.getScheme() + " at " + target + "; refusing to follow it");
        }
        if (!allowedHosts.contains(target.getHost())) {
            throw new IOException(
                    "A redirect pointed outside the allowed hosts at " + target
                            + "; refusing to follow it");
        }
    }

    private static HttpRequest rebuildRequest(HttpRequest request, URI target) {
        return HttpRequest.newBuilder(target)
                .timeout(Duration.ofSeconds(60))
                .header("User-Agent", "neo4j-cert-tool/" + currentVersionForUserAgent())
                .header("Accept", "application/vnd.github+json")
                .GET()
                .build();
    }

    private static void requireOkay(String url, int status) throws IOException {
        if (status == 404) {
            throw new IOException("Nothing was found at " + url + " (no such release or tag)");
        }
        if (status != 200) {
            // Redirects are followed by the client itself, so anything here is an error.
            throw new IOException(url + " answered with HTTP " + status);
        }
    }
}
