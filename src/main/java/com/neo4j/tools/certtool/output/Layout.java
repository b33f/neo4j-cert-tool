package com.neo4j.tools.certtool.output;

import com.neo4j.tools.certtool.model.Scope;
import java.nio.file.Path;

/**
 * The on-disk layout Neo4j expects, and the staging layout this tool writes.
 *
 * <p>File and directory names match the defaults of
 * {@code dbms.ssl.policy.<scope>.private_key}, {@code .public_certificate}, {@code .trusted_dir}
 * and {@code .revoked_dir}, so a generated bundle works without overriding any of them.
 */
public final class Layout {

    public static final String CERTIFICATES_DIRECTORY = "certificates";
    public static final String PRIVATE_KEY_FILE = "private.key";
    public static final String PUBLIC_CERTIFICATE_FILE = "public.crt";
    public static final String TRUSTED_DIRECTORY = "trusted";
    public static final String REVOKED_DIRECTORY = "revoked";

    public static final String CONF_SNIPPET_FILE = "neo4j.conf.snippet";
    public static final String CA_DIRECTORY = "ca";
    public static final String CA_CERTIFICATE_FILE = "ca.crt";
    public static final String CA_KEY_FILE = "ca.key";
    public static final String INTERMEDIATE_CERTIFICATE_FILE = "intermediate.crt";
    public static final String INTERMEDIATE_KEY_FILE = "intermediate.key";
    public static final String CA_README_FILE = "README.txt";

    private Layout() {}

    /** The {@code certificates} directory inside a node bundle or a Neo4j installation. */
    public static Path certificates(Path root) {
        return root.resolve(CERTIFICATES_DIRECTORY);
    }

    /** The directory for one policy scope. */
    public static Path scope(Path root, Scope scope) {
        return certificates(root).resolve(scope.directoryName());
    }

    public static Path privateKey(Path root, Scope scope) {
        return scope(root, scope).resolve(PRIVATE_KEY_FILE);
    }

    public static Path publicCertificate(Path root, Scope scope) {
        return scope(root, scope).resolve(PUBLIC_CERTIFICATE_FILE);
    }

    public static Path trusted(Path root, Scope scope) {
        return scope(root, scope).resolve(TRUSTED_DIRECTORY);
    }

    public static Path revoked(Path root, Scope scope) {
        return scope(root, scope).resolve(REVOKED_DIRECTORY);
    }
}
