package com.neo4j.tools.certtool.model;

import com.neo4j.tools.certtool.crypto.Extensions;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/**
 * One cluster member: a short name used for its output directory, and every address a peer might
 * use to reach it.
 *
 * @param name short identifier, also the output directory name
 * @param subjectAlternativeNames DNS names and IP literals, in the order they were given
 */
public record NodeSpec(String name, List<String> subjectAlternativeNames) {

    public NodeSpec {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("A node needs a name");
        }
        if (!name.matches("[A-Za-z0-9][A-Za-z0-9._-]*")) {
            // The name becomes a directory name, so keep it free of path separators and surprises.
            throw new IllegalArgumentException(
                    "Node name '" + name + "' must contain only letters, digits, dot, dash "
                            + "or underscore, and start with a letter or digit");
        }
        if (subjectAlternativeNames == null || subjectAlternativeNames.isEmpty()) {
            throw new IllegalArgumentException(
                    "Node '" + name + "' needs at least one DNS name or IP address");
        }
        subjectAlternativeNames = List.copyOf(subjectAlternativeNames);
    }

    /**
     * Parses the {@code --node} argument form {@code name:san[,san...]}, where the names after the
     * colon are optional and default to the node name.
     *
     * <p>IPv6 literals contain colons, so the split is on the first colon only.
     */
    public static NodeSpec parse(String specification) {
        String trimmed = specification.trim();
        if (trimmed.isEmpty()) {
            throw new IllegalArgumentException("Empty --node value");
        }
        int separator = trimmed.indexOf(':');
        String name = separator < 0 ? trimmed : trimmed.substring(0, separator).trim();
        String names = separator < 0 ? "" : trimmed.substring(separator + 1);
        return of(name, names);
    }

    /**
     * Builds a node from its name and a comma-separated list of addresses. When the list is empty
     * the node name is used as the sole DNS name.
     */
    public static NodeSpec of(String name, String commaSeparatedNames) {
        LinkedHashSet<String> sans = new LinkedHashSet<>();
        for (String part : commaSeparatedNames.split(",")) {
            String candidate = part.trim();
            if (!candidate.isEmpty()) {
                sans.add(normalise(candidate));
            }
        }
        if (sans.isEmpty()) {
            sans.add(normalise(name));
        }
        return new NodeSpec(name, new ArrayList<>(sans));
    }

    /**
     * DNS names are compared case-insensitively, so store them lower case to keep the certificate
     * canonical. IP literals are left as given.
     */
    private static String normalise(String value) {
        return Extensions.asIpLiteral(value) != null ? value : value.toLowerCase(Locale.ROOT);
    }

    /**
     * The common name for the certificate subject.
     *
     * <p>Modern TLS clients validate hostnames against the SAN and ignore the common name, but it
     * is still what appears in logs and in {@code openssl x509} output, so it should be the
     * node's primary DNS name.
     */
    public String commonName() {
        for (String san : subjectAlternativeNames) {
            if (Extensions.asIpLiteral(san) == null) {
                return san;
            }
        }
        // An IP-only node: fall back to the first address so the subject is never empty.
        return subjectAlternativeNames.getFirst();
    }
}
