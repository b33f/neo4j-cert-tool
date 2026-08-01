package com.neo4j.tools.certtool;

import com.neo4j.tools.certtool.crypto.Pkcs8;
import com.neo4j.tools.certtool.model.KeyType;
import com.neo4j.tools.certtool.model.NodeSpec;
import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.model.TrustMode;
import java.nio.file.Path;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * A fully resolved set of options for one run.
 *
 * @param command what the tool was asked to do
 * @param trustMode how trust is established between nodes
 * @param nodes the cluster members to issue certificates for
 * @param scopes the Neo4j SSL policy scopes to populate
 * @param keyType the key algorithm for every generated key, including the CA's
 * @param validityDays lifetime of leaf certificates
 * @param caValidityDays lifetime of CA certificates
 * @param outputDirectory root of the generated per-node bundles
 * @param installNode name of the node whose bundle should be copied into {@code neo4jHome}
 * @param neo4jHome installation to copy into, when installing
 * @param passwordMode where private key passwords come from
 * @param passwordFile password file, when {@code passwordMode} is FILE
 * @param sharedPassword prompt once and use the same password for every key
 * @param pbkdf2Iterations PBKDF2 iteration count for private key encryption
 * @param existingCaCertificate an existing CA certificate to issue from, instead of a new one
 * @param existingCaKey the matching CA private key
 * @param caPasswordFile password file for an existing CA key
 * @param nameConstraints whether to bind a generated CA to the names it was created for
 * @param permitDns extra DNS subtrees the CA may issue within
 * @param permitIp extra address ranges the CA may issue within
 * @param owner {@code user[:group]} to give the generated files, when running as root
 * @param dryRun report what would be done and write nothing
 * @param force overwrite non-empty output directories
 * @param quiet suppress the informational summary
 */
public record Options(
        Command command,
        TrustMode trustMode,
        List<NodeSpec> nodes,
        Set<Scope> scopes,
        KeyType keyType,
        int validityDays,
        int caValidityDays,
        Path outputDirectory,
        Optional<String> installNode,
        Optional<Path> neo4jHome,
        Subject subject,
        PasswordProvider.Mode passwordMode,
        Optional<Path> passwordFile,
        boolean sharedPassword,
        int pbkdf2Iterations,
        Optional<Path> existingCaCertificate,
        Optional<Path> existingCaKey,
        Optional<Path> caPasswordFile,
        boolean nameConstraints,
        List<String> permitDns,
        List<String> permitIp,
        Optional<String> owner,
        boolean dryRun,
        boolean force,
        boolean quiet) {

    /** What the tool was asked to do. */
    public enum Command {
        GENERATE,
        VERIFY,
        HELP,
        VERSION
    }

    /**
     * The naming attributes shared by every generated certificate.
     *
     * @param organisation the {@code O} attribute
     * @param organisationalUnit the {@code OU} attribute
     * @param country the two-letter {@code C} attribute
     * @param locality the {@code L} attribute
     * @param state the {@code ST} attribute
     * @param caCommonName common name of the root CA
     * @param intermediateCommonName common name of the intermediate CA
     */
    public record Subject(
            String organisation,
            String organisationalUnit,
            String country,
            String locality,
            String state,
            String caCommonName,
            String intermediateCommonName) {}

    public static final String DEFAULT_ORGANISATION = "Neo4j Cluster";
    public static final String DEFAULT_CA_COMMON_NAME = "Neo4j Cluster Root CA";
    public static final String DEFAULT_INTERMEDIATE_COMMON_NAME = "Neo4j Cluster Issuing CA";

    /**
     * Default leaf certificate lifetime, in days: 13 months, matching the maximum lifetime public
     * CAs are permitted to issue and short enough to keep rotation a practised routine.
     */
    public static final int DEFAULT_VALIDITY_DAYS = 397;

    /** Default CA lifetime, in days: 10 years, so the trust anchor outlives several leaf rotations. */
    public static final int DEFAULT_CA_VALIDITY_DAYS = 3650;

    public static final Path DEFAULT_OUTPUT_DIRECTORY = Path.of("out");

    /** The options a bare {@code generate} run would use, before any argument is applied. */
    public static Options defaults() {
        return new Options(
                Command.GENERATE,
                TrustMode.CA,
                List.of(),
                EnumSet.allOf(Scope.class),
                KeyType.EC_P256,
                DEFAULT_VALIDITY_DAYS,
                DEFAULT_CA_VALIDITY_DAYS,
                DEFAULT_OUTPUT_DIRECTORY,
                Optional.empty(),
                Optional.empty(),
                new Subject(
                        DEFAULT_ORGANISATION,
                        null,
                        null,
                        null,
                        null,
                        DEFAULT_CA_COMMON_NAME,
                        DEFAULT_INTERMEDIATE_COMMON_NAME),
                PasswordProvider.Mode.PROMPT,
                Optional.empty(),
                false,
                Pkcs8.DEFAULT_ITERATIONS,
                Optional.empty(),
                Optional.empty(),
                Optional.empty(),
                true,
                List.of(),
                List.of(),
                Optional.empty(),
                false,
                false,
                false);
    }
}
