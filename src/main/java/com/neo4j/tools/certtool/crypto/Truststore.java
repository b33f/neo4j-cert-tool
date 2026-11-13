package com.neo4j.tools.certtool.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Builds and reads the PKCS#12 truststore of a run's trust anchors, for Java clients.
 *
 * <p>Neo4j itself reads trust anchors from a directory of PEM files, and so do OpenSSL, curl and
 * most scripting languages. The JVM cannot: its default {@code TrustManagerFactory} loads trust
 * material from a keystore, typically PKCS#12. Every Java client of the cluster —
 * {@code cypher-shell}, a driver application, a Spring Data service — needs the CA in that form,
 * so the tool writes one alongside the bundles rather than leaving each user to reassemble it
 * with {@code keytool}.
 *
 * <p>The truststore holds <em>public</em> certificates only. A Java keystore can hold two very
 * different things: private keys, which must be kept secret, and trusted public certificates,
 * which need not — a keystore holding only the latter is a truststore. The same public root
 * certificates ship openly with every operating system and browser, and the JDK's own
 * {@code cacerts} file is a truststore of them with this same password, so encrypting public
 * material with a secret password would add no security.
 *
 * <p>The password still does two jobs, just not secrecy. In the JKS and PKCS#12 formats it keys a
 * cryptographic checksum that detects corruption or tampering when the store is loaded; and
 * requiring a password — even a publicly known one — acts as a minor guardrail in utilities like
 * {@code keytool}, which pause for explicit intent before an administrator modifies a truststore
 * by accident. It is still a password the keystore APIs demand on every load.
 */
public final class Truststore {

    /**
     * The password of the generated truststore: the JVM's long-standing default, which is what a
     * truststore of public certificates deserves. Nothing here is secret.
     */
    public static final char[] PASSWORD = "changeit".toCharArray();

    private Truststore() {}

    /**
     * Encodes trust anchors as a PKCS#12 keystore.
     *
     * <p>Entries are written in map order, which the callers fix so the output is reproducible.
     * PKCS#12 keystores embed a MAC whose salt is random, so two stores of the same anchors are
     * never byte-identical — equality of content is checked by loading, not by comparing files.
     */
    public static byte[] pkcs12(Map<String, X509Certificate> anchors) throws GeneralSecurityException {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            for (Map.Entry<String, X509Certificate> anchor : anchors.entrySet()) {
                keyStore.setCertificateEntry(anchor.getKey(), anchor.getValue());
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            keyStore.store(out, PASSWORD);
            return out.toByteArray();
        } catch (IOException e) {
            // A keystore built entirely in memory cannot fail on I/O; wrap for the callers that
            // are already IOException-literate.
            throw new GeneralSecurityException("cannot build the client truststore: " + e.getMessage(), e);
        }
    }

    /**
     * Loads a generated truststore file and returns its certificates, in alias order.
     *
     * @throws GeneralSecurityException when the file is not a PKCS#12 keystore or the password
     *     is wrong, which is how {@code verify} reports a damaged or replaced truststore
     */
    public static List<X509Certificate> anchors(Path file)
            throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(file)) {
            keyStore.load(in, PASSWORD);
        }
        List<X509Certificate> anchors = new ArrayList<>();
        for (var aliases = keyStore.aliases(); aliases.hasMoreElements(); ) {
            String alias = aliases.nextElement();
            anchors.add((X509Certificate) keyStore.getCertificate(alias));
        }
        return List.copyOf(anchors);
    }
}
