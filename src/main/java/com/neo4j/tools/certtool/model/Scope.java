package com.neo4j.tools.certtool.model;

import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * The four Neo4j SSL policy scopes.
 *
 * <p>Each scope is an independent policy in {@code neo4j.conf} with its own directory under
 * {@code <neo4j-home>/certificates/}. The scopes differ in whether the peer is authenticated:
 * {@code cluster} and {@code backup} default to {@code client_auth=REQUIRE}, so certificates used
 * there must be valid for client authentication as well as server authentication.
 */
public enum Scope {
    BOLT("bolt", "Bolt driver connections (neo4j:// and bolt+s://)", false, "OPTIONAL"),
    HTTPS("https", "The HTTPS server, including Neo4j Browser", false, "OPTIONAL"),
    CLUSTER("cluster", "Intra-cluster communication between cluster members", true, "REQUIRE"),
    BACKUP("backup", "Backup and restore traffic (neo4j-admin database backup)", true, "REQUIRE");

    private final String directoryName;
    private final String purpose;
    private final boolean mutualAuthentication;
    private final String defaultClientAuth;

    Scope(String directoryName, String purpose, boolean mutualAuthentication, String defaultClientAuth) {
        this.directoryName = directoryName;
        this.purpose = purpose;
        this.mutualAuthentication = mutualAuthentication;
        this.defaultClientAuth = defaultClientAuth;
    }

    /** The directory name under {@code certificates/}, which is also the config setting name. */
    public String directoryName() {
        return directoryName;
    }

    public String purpose() {
        return purpose;
    }

    /**
     * Whether the certificate must also be usable as a client certificate.
     *
     * <p>Cluster members connect to each other in both directions, and backup clients authenticate
     * to the server, so both scopes need {@code clientAuth} in their extended key usage.
     */
    public boolean mutualAuthentication() {
        return mutualAuthentication;
    }

    /** Neo4j's default {@code client_auth} for this scope, quoted in the generated config. */
    public String defaultClientAuth() {
        return defaultClientAuth;
    }

    public String configPrefix() {
        return "dbms.ssl.policy." + directoryName;
    }

    public static Scope parse(String value) {
        String normalised = value.trim().toLowerCase(Locale.ROOT);
        for (Scope scope : values()) {
            if (scope.directoryName.equals(normalised)) {
                return scope;
            }
        }
        throw new IllegalArgumentException(
                "Unknown scope '" + value + "'. Choose from: " + names());
    }

    /** Parses a comma-separated scope list, preserving declaration order and rejecting duplicates. */
    public static Set<Scope> parseList(String value) {
        Set<Scope> scopes = new LinkedHashSet<>();
        for (String part : value.split(",")) {
            if (part.isBlank()) {
                continue;
            }
            if (!scopes.add(parse(part))) {
                throw new IllegalArgumentException("Scope listed twice: " + part.trim());
            }
        }
        if (scopes.isEmpty()) {
            throw new IllegalArgumentException("No scopes selected");
        }
        return scopes;
    }

    public static String names() {
        return java.util.Arrays.stream(values())
                .map(Scope::directoryName)
                .collect(Collectors.joining(", "));
    }
}
