package com.neo4j.tools.certtool;

import com.neo4j.tools.certtool.crypto.DistinguishedName;
import com.neo4j.tools.certtool.crypto.Extensions;
import com.neo4j.tools.certtool.crypto.Extensions.KeyUsage;
import com.neo4j.tools.certtool.crypto.Oids;
import com.neo4j.tools.certtool.crypto.SignatureAlgorithm;
import com.neo4j.tools.certtool.crypto.X509Builder;
import com.neo4j.tools.certtool.model.NodeSpec;
import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.model.TrustMode;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Issues the certificates for one run.
 *
 * <p>Every node gets its own key pair for every scope, so a key compromised on one channel does
 * not extend to the others.
 */
public final class CertificateGenerator {

    /** A certificate authority, either newly created here or loaded from an earlier run. */
    public record Authority(
            String label,
            X509Certificate certificate,
            PrivateKey privateKey,
            DistinguishedName subject,
            boolean newlyCreated) {}

    /** A certificate to be written into a {@code trusted/} directory. */
    public record TrustAnchor(String fileName, X509Certificate certificate) {}

    /**
     * The material for one node and one scope.
     *
     * @param certificateChain leaf certificate first, followed by any intermediates
     */
    public record ScopeMaterial(
            Scope scope,
            PrivateKey privateKey,
            List<X509Certificate> certificateChain,
            List<TrustAnchor> trustAnchors) {

        public X509Certificate certificate() {
            return certificateChain.getFirst();
        }
    }

    /** Everything generated for one node. */
    public record NodeBundle(NodeSpec node, List<ScopeMaterial> scopes) {}

    /** The outcome of a run, before anything is written to disk. */
    public record Result(List<Authority> authorities, List<NodeBundle> nodes) {

        /** The trust anchor every node validates against, if there is a CA. */
        public Optional<Authority> rootAuthority() {
            return authorities.isEmpty() ? Optional.empty() : Optional.of(authorities.getFirst());
        }
    }

    private final Options options;
    private final SecureRandom random;
    private final Instant now;

    public CertificateGenerator(Options options, SecureRandom random, Instant now) {
        this.options = options;
        this.random = random;
        this.now = now;
    }

    /**
     * Generates all certificates.
     *
     * @param existingRoot a CA loaded from a previous run, to issue from instead of creating one
     */
    public Result generate(Optional<Authority> existingRoot) throws GeneralSecurityException {
        return options.trustMode() == TrustMode.SELF_SIGNED
                ? generateSelfSigned()
                : generateFromAuthority(existingRoot);
    }

    // --- CA-backed modes -------------------------------------------------------------------

    private Result generateFromAuthority(Optional<Authority> existingRoot)
            throws GeneralSecurityException {
        boolean twoTier = options.trustMode() == TrustMode.INTERMEDIATE;

        Authority root = existingRoot.isPresent()
                ? validateExistingRoot(existingRoot.get(), twoTier)
                : createRootAuthority(twoTier ? 1 : 0);

        List<Authority> authorities = new ArrayList<>();
        authorities.add(root);

        Authority issuer = root;
        if (twoTier) {
            Authority intermediate = createIntermediateAuthority(root);
            authorities.add(intermediate);
            issuer = intermediate;
        }

        // Nodes trust the root only. When there is an intermediate, it travels with the leaf in
        // public.crt instead, which is how a TLS peer is expected to receive it.
        List<TrustAnchor> anchors = List.of(new TrustAnchor("root-ca.crt", root.certificate()));
        List<X509Certificate> intermediates = twoTier ? List.of(issuer.certificate()) : List.of();

        List<NodeBundle> bundles = new ArrayList<>();
        for (NodeSpec node : options.nodes()) {
            List<ScopeMaterial> scopes = new ArrayList<>();
            for (Scope scope : orderedScopes()) {
                KeyPair keyPair = options.keyType().generate(random);
                X509Certificate leaf = issueLeaf(node, scope, keyPair.getPublic(), issuer);

                List<X509Certificate> chain = new ArrayList<>();
                chain.add(leaf);
                chain.addAll(intermediates);
                scopes.add(new ScopeMaterial(scope, keyPair.getPrivate(), List.copyOf(chain), anchors));
            }
            bundles.add(new NodeBundle(node, List.copyOf(scopes)));
        }
        return new Result(List.copyOf(authorities), List.copyOf(bundles));
    }

    private Authority validateExistingRoot(Authority root, boolean twoTier)
            throws GeneralSecurityException {
        X509Certificate certificate = root.certificate();
        int pathLength = certificate.getBasicConstraints();
        if (pathLength == -1) {
            throw new GeneralSecurityException(
                    "The certificate supplied with --ca-cert is not a CA certificate "
                            + "(it has no basicConstraints cA flag), so it cannot sign certificates");
        }
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage != null && keyUsage.length > 5 && !keyUsage[5]) {
            throw new GeneralSecurityException(
                    "The certificate supplied with --ca-cert does not permit keyCertSign, "
                            + "so it cannot sign certificates");
        }
        if (twoTier && pathLength == 0) {
            throw new GeneralSecurityException(
                    """
                    The CA supplied with --ca-cert has pathLenConstraint=0, so it may only issue \
                    end-entity certificates and cannot sign an intermediate CA. Either issue \
                    leaves directly with --mode ca, or create a new two-tier hierarchy without \
                    --ca-cert.""");
        }
        certificate.checkValidity(java.util.Date.from(now));
        return root;
    }

    private Authority createRootAuthority(int pathLenConstraint) throws GeneralSecurityException {
        KeyPair keyPair = options.keyType().generate(random);
        DistinguishedName subject = authoritySubject(options.subject().caCommonName());
        X509Certificate certificate = buildCaCertificate(
                subject, subject, keyPair.getPublic(), keyPair.getPrivate(), pathLenConstraint, null);
        return new Authority("root CA", certificate, keyPair.getPrivate(), subject, true);
    }

    private Authority createIntermediateAuthority(Authority root) throws GeneralSecurityException {
        KeyPair keyPair = options.keyType().generate(random);
        DistinguishedName subject = authoritySubject(options.subject().intermediateCommonName());
        X509Certificate certificate = buildCaCertificate(
                subject,
                root.subject(),
                keyPair.getPublic(),
                root.privateKey(),
                0,
                root.certificate().getPublicKey());
        return new Authority("intermediate CA", certificate, keyPair.getPrivate(), subject, true);
    }

    private X509Certificate buildCaCertificate(
            DistinguishedName subject,
            DistinguishedName issuer,
            PublicKey subjectKey,
            PrivateKey signingKey,
            int pathLenConstraint,
            PublicKey issuerKey)
            throws GeneralSecurityException {
        X509Builder builder = new X509Builder(random)
                .subject(subject)
                .issuer(issuer)
                .publicKey(subjectKey)
                .validity(now, options.caValidityDays())
                .addExtension(Extensions.basicConstraintsCa(pathLenConstraint))
                .addExtension(Extensions.keyUsage(KeyUsage.KEY_CERT_SIGN, KeyUsage.CRL_SIGN))
                .addExtension(Extensions.subjectKeyIdentifier(subjectKey))
                .addExtension(
                        Extensions.authorityKeyIdentifier(issuerKey != null ? issuerKey : subjectKey));
        return builder.signWith(signingKey, SignatureAlgorithm.forSigningKey(signingKey));
    }

    private X509Certificate issueLeaf(
            NodeSpec node, Scope scope, PublicKey subjectKey, Authority issuer)
            throws GeneralSecurityException {
        X509Builder builder = new X509Builder(random)
                .subject(leafSubject(node, scope))
                .issuer(issuer.subject())
                .publicKey(subjectKey)
                .validity(now, options.validityDays())
                .addExtension(Extensions.basicConstraintsEndEntity())
                .addExtension(keyUsageForLeaf())
                .addExtension(extendedKeyUsageFor(scope))
                .addExtension(Extensions.subjectAlternativeName(node.subjectAlternativeNames()))
                .addExtension(Extensions.subjectKeyIdentifier(subjectKey))
                .addExtension(Extensions.authorityKeyIdentifier(issuer.certificate().getPublicKey()));
        return builder.signWith(
                issuer.privateKey(), SignatureAlgorithm.forSigningKey(issuer.privateKey()));
    }

    // --- Self-signed mode ------------------------------------------------------------------

    private Result generateSelfSigned() throws GeneralSecurityException {
        // Generate every node's material first: each node has to trust all of the others, so the
        // trusted/ contents are only known once every certificate exists.
        Map<NodeSpec, Map<Scope, KeyPair>> keys = new LinkedHashMap<>();
        Map<NodeSpec, Map<Scope, X509Certificate>> certificates = new LinkedHashMap<>();

        for (NodeSpec node : options.nodes()) {
            Map<Scope, KeyPair> nodeKeys = new LinkedHashMap<>();
            Map<Scope, X509Certificate> nodeCertificates = new LinkedHashMap<>();
            for (Scope scope : orderedScopes()) {
                KeyPair keyPair = options.keyType().generate(random);
                DistinguishedName subject = leafSubject(node, scope);
                X509Builder builder = new X509Builder(random)
                        .subject(subject)
                        .issuer(subject)
                        .publicKey(keyPair.getPublic())
                        .validity(now, options.validityDays())
                        .addExtension(Extensions.basicConstraintsEndEntity())
                        .addExtension(keyUsageForLeaf())
                        .addExtension(extendedKeyUsageFor(scope))
                        .addExtension(
                                Extensions.subjectAlternativeName(node.subjectAlternativeNames()))
                        .addExtension(Extensions.subjectKeyIdentifier(keyPair.getPublic()));
                nodeKeys.put(scope, keyPair);
                nodeCertificates.put(
                        scope,
                        builder.signWith(
                                keyPair.getPrivate(),
                                SignatureAlgorithm.forSigningKey(keyPair.getPrivate())));
            }
            keys.put(node, nodeKeys);
            certificates.put(node, nodeCertificates);
        }

        List<NodeBundle> bundles = new ArrayList<>();
        for (NodeSpec node : options.nodes()) {
            List<ScopeMaterial> scopes = new ArrayList<>();
            for (Scope scope : orderedScopes()) {
                // Every node's own certificate is included, because a member may connect to
                // itself through the same policy.
                List<TrustAnchor> anchors = new ArrayList<>();
                for (NodeSpec peer : options.nodes()) {
                    anchors.add(new TrustAnchor(
                            peer.name() + ".crt", certificates.get(peer).get(scope)));
                }
                scopes.add(new ScopeMaterial(
                        scope,
                        keys.get(node).get(scope).getPrivate(),
                        List.of(certificates.get(node).get(scope)),
                        List.copyOf(anchors)));
            }
            bundles.add(new NodeBundle(node, List.copyOf(scopes)));
        }
        return new Result(List.of(), List.copyOf(bundles));
    }

    // --- Shared pieces ---------------------------------------------------------------------

    /** Iterates the selected scopes in declaration order, so output is reproducible. */
    private List<Scope> orderedScopes() {
        List<Scope> ordered = new ArrayList<>();
        for (Scope scope : Scope.values()) {
            if (options.scopes().contains(scope)) {
                ordered.add(scope);
            }
        }
        return ordered;
    }

    private DistinguishedName authoritySubject(String commonName) {
        return baseSubject().commonName(commonName).build();
    }

    /**
     * The subject for a node's certificate. The organisational unit names the scope, so that
     * {@code openssl x509} output makes it obvious which policy a certificate belongs to.
     */
    private DistinguishedName leafSubject(NodeSpec node, Scope scope) {
        DistinguishedName.Builder builder = baseSubject();
        String unit = options.subject().organisationalUnit();
        builder.add(
                Oids.ORGANISATIONAL_UNIT,
                unit == null || unit.isBlank() ? scope.directoryName() : unit + " " + scope.directoryName());
        return builder.commonName(node.commonName()).build();
    }

    private DistinguishedName.Builder baseSubject() {
        Options.Subject subject = options.subject();
        return DistinguishedName.builder()
                .add(Oids.ORGANISATION, subject.organisation())
                .add(Oids.ORGANISATIONAL_UNIT, subject.organisationalUnit())
                .add(Oids.LOCALITY, subject.locality())
                .add(Oids.STATE, subject.state())
                .country(subject.country());
    }

    /**
     * Key usage for an end-entity certificate.
     *
     * <p>ECDSA keys only ever sign during a handshake. RSA keys additionally need
     * {@code keyEncipherment} for the RSA key transport suites that TLS 1.2 clients may still
     * offer.
     */
    private Extensions.Extension keyUsageForLeaf() {
        return "RSA".equals(options.keyType().jcaAlgorithm())
                ? Extensions.keyUsage(KeyUsage.DIGITAL_SIGNATURE, KeyUsage.KEY_ENCIPHERMENT)
                : Extensions.keyUsage(KeyUsage.DIGITAL_SIGNATURE);
    }

    /**
     * Extended key usage for a scope.
     *
     * <p>Cluster members authenticate each other in both directions, and backup clients present a
     * certificate to the server, so those scopes need {@code clientAuth} as well as
     * {@code serverAuth}.
     */
    private Extensions.Extension extendedKeyUsageFor(Scope scope) {
        return scope.mutualAuthentication()
                ? Extensions.extendedKeyUsage(Oids.EKU_SERVER_AUTH, Oids.EKU_CLIENT_AUTH)
                : Extensions.extendedKeyUsage(Oids.EKU_SERVER_AUTH);
    }
}
