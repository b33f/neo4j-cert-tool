package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.neo4j.tools.certtool.model.KeyType;
import com.neo4j.tools.certtool.model.NodeSpec;
import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.model.TrustMode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Checks argument and configuration file parsing. */
class CliTest {

    private static Options parse(String... arguments) throws Cli.UsageException {
        return Cli.parse(arguments);
    }

    @Nested
    @DisplayName("defaults")
    class Defaults {

        @Test
        void areTheSafeChoices() throws Exception {
            Options options = parse("--node", "core1");

            assertEquals(Options.Command.GENERATE, options.command());
            assertEquals(TrustMode.CA, options.trustMode(), "a CA is right for almost every cluster");
            assertEquals(KeyType.EC_P256, options.keyType());
            assertEquals(Set.of(Scope.values()), options.scopes(), "all four scopes by default");
            assertEquals(397, options.validityDays());
            assertEquals(3650, options.caValidityDays());
            assertEquals(PasswordProvider.Mode.PROMPT, options.passwordMode());
            assertEquals(600_000, options.pbkdf2Iterations());
            assertFalse(options.force());
            assertTrue(options.installNode().isEmpty(), "nothing is installed unless asked for");
        }

        @Test
        void matchTheDefaultsRecord() {
            Options defaults = Options.defaults();
            assertEquals(TrustMode.CA, defaults.trustMode());
            assertEquals(KeyType.EC_P256, defaults.keyType());
        }
    }

    @Nested
    @DisplayName("node specifications")
    class Nodes {

        @Test
        void takeTheirNamesFromTheArgument() throws Exception {
            Options options = parse("--node", "core1:core1.example.com,10.0.0.11");

            NodeSpec node = options.nodes().getFirst();
            assertEquals("core1", node.name());
            assertEquals(List.of("core1.example.com", "10.0.0.11"), node.subjectAlternativeNames());
            assertEquals("core1.example.com", node.commonName());
        }

        @Test
        void defaultToTheNodeNameWhenNoNamesAreGiven() throws Exception {
            Options options = parse("--node", "core1.example.com");

            NodeSpec node = options.nodes().getFirst();
            assertEquals("core1.example.com", node.name());
            assertEquals(List.of("core1.example.com"), node.subjectAlternativeNames());
        }

        @Test
        void splitOnTheFirstColonSoIpv6LiteralsSurvive() throws Exception {
            Options options = parse("--node", "core1:::1,fe80::1,core1.example.com");

            assertEquals(
                    List.of("::1", "fe80::1", "core1.example.com"),
                    options.nodes().getFirst().subjectAlternativeNames());
        }

        @Test
        void areAccumulatedInOrder() throws Exception {
            Options options = parse("--node", "a", "--node", "b", "--node", "c");

            assertEquals(List.of("a", "b", "c"), options.nodes().stream().map(NodeSpec::name).toList());
        }

        @Test
        void lowerCaseDnsNamesButLeaveAddressesAlone() throws Exception {
            Options options = parse("--node", "core1:CORE1.Example.COM,10.0.0.11");

            assertEquals(
                    List.of("core1.example.com", "10.0.0.11"),
                    options.nodes().getFirst().subjectAlternativeNames());
        }

        @Test
        void deduplicateRepeatedNames() throws Exception {
            Options options = parse("--node", "core1:a.example.com,a.example.com,A.EXAMPLE.COM");

            assertEquals(List.of("a.example.com"), options.nodes().getFirst().subjectAlternativeNames());
        }

        @Test
        void rejectDuplicateNodeNames() {
            Cli.UsageException failure =
                    assertThrows(Cli.UsageException.class, () -> parse("--node", "a", "--node", "a"));
            assertTrue(failure.getMessage().contains("defined twice"), failure.getMessage());
        }

        @Test
        void rejectNamesThatWouldEscapeTheOutputDirectory() {
            assertThrows(Cli.UsageException.class, () -> parse("--node", "../etc:a.example.com"));
            assertThrows(Cli.UsageException.class, () -> parse("--node", "a/b:a.example.com"));
        }

        @Test
        void areRequiredForGeneration() {
            Cli.UsageException failure = assertThrows(Cli.UsageException.class, () -> parse());
            assertTrue(failure.getMessage().contains("--node"), failure.getMessage());
        }
    }

    @Nested
    @DisplayName("option syntax")
    class Syntax {

        @Test
        void acceptsSpaceSeparatedAndEqualsForms() throws Exception {
            assertEquals(TrustMode.SELF_SIGNED, parse("--node", "a", "--mode", "self-signed").trustMode());
            assertEquals(TrustMode.SELF_SIGNED, parse("--node", "a", "--mode=self-signed").trustMode());
        }

        @Test
        void treatsALeadingBareWordAsTheCommand() throws Exception {
            assertEquals(Options.Command.VERIFY, parse("verify", "--out", "x").command());
            assertEquals(Options.Command.GENERATE, parse("generate", "--node", "a").command());
            assertEquals(Options.Command.HELP, parse("help").command());
            assertEquals(Options.Command.VERSION, parse("version").command());
        }

        @Test
        void recognisesHelpAndVersionFlagsAnywhere() throws Exception {
            assertEquals(Options.Command.HELP, parse("--help").command());
            assertEquals(Options.Command.HELP, parse("-h").command());
            assertEquals(Options.Command.VERSION, parse("--version").command());
            assertEquals(Options.Command.HELP, parse("--node", "a", "--help").command());
        }

        @Test
        void reportsAnUnknownOption() {
            Cli.UsageException failure =
                    assertThrows(Cli.UsageException.class, () -> parse("--node", "a", "--nope", "x"));
            assertTrue(failure.getMessage().contains("--nope"), failure.getMessage());
        }

        @Test
        void reportsAnUnknownCommand() {
            assertThrows(Cli.UsageException.class, () -> parse("frobnicate"));
        }

        @Test
        void reportsAMissingValue() {
            Cli.UsageException failure =
                    assertThrows(Cli.UsageException.class, () -> parse("--node", "a", "--mode"));
            assertTrue(failure.getMessage().contains("needs a value"), failure.getMessage());
        }

        @Test
        void reportsAStrayPositionalArgument() {
            assertThrows(Cli.UsageException.class, () -> parse("--node", "a", "stray"));
        }

        @Test
        void acceptsBothSpellingsOfOrganisation() throws Exception {
            assertEquals("X", parse("--node", "a", "--organization", "X").subject().organisation());
            assertEquals("X", parse("--node", "a", "--organisation", "X").subject().organisation());
            assertEquals(
                    "Y", parse("--node", "a", "--organizational-unit", "Y").subject().organisationalUnit());
        }
    }

    @Nested
    @DisplayName("value validation")
    class Validation {

        @ParameterizedTest
        @CsvSource({"ec, EC_P256", "ec-p256, EC_P256", "ec-p384, EC_P384", "rsa, RSA_4096", "rsa-3072, RSA_3072"})
        void keyTypesAndTheirAliases(String argument, KeyType expected) throws Exception {
            assertEquals(expected, parse("--node", "a", "--key-type", argument).keyType());
        }

        @Test
        void anUnknownKeyTypeListsTheValidOnes() {
            Cli.UsageException failure = assertThrows(
                    Cli.UsageException.class, () -> parse("--node", "a", "--key-type", "dsa"));
            assertTrue(failure.getMessage().contains("ec-p256"), failure.getMessage());
        }

        @Test
        void scopeListsPreserveOrderAndRejectDuplicates() throws Exception {
            assertEquals(
                    Set.of(Scope.BOLT, Scope.HTTPS),
                    parse("--node", "a", "--scopes", "bolt,https").scopes());
            assertThrows(
                    Cli.UsageException.class, () -> parse("--node", "a", "--scopes", "bolt,bolt"));
            assertThrows(Cli.UsageException.class, () -> parse("--node", "a", "--scopes", "raft"));
            assertThrows(Cli.UsageException.class, () -> parse("--node", "a", "--scopes", ""));
        }

        @ParameterizedTest
        @ValueSource(strings = {"0", "-1", "7301", "many"})
        void validityMustBeAReasonableNumberOfDays(String value) {
            assertThrows(
                    Cli.UsageException.class, () -> parse("--node", "a", "--validity-days", value));
        }

        @Test
        void iterationCountsBelowTheFloorAreRejected() {
            Cli.UsageException failure = assertThrows(
                    Cli.UsageException.class,
                    () -> parse("--node", "a", "--pbkdf2-iterations", "1000"));
            assertTrue(failure.getMessage().contains("at least 10000"), failure.getMessage());
        }

        @Test
        void countryMustBeTwoLetters() {
            assertThrows(
                    Cli.UsageException.class, () -> parse("--node", "a", "--country", "United Kingdom"));
        }

        @Test
        void aCaCertificateNeedsItsKey() {
            assertThrows(
                    Cli.UsageException.class, () -> parse("--node", "a", "--ca-cert", "ca.crt"));
            assertThrows(Cli.UsageException.class, () -> parse("--node", "a", "--ca-key", "ca.key"));
        }

        @Test
        void selfSignedModeHasNoCaToReuse() {
            Cli.UsageException failure = assertThrows(
                    Cli.UsageException.class,
                    () -> parse(
                            "--node", "a",
                            "--mode", "self-signed",
                            "--ca-cert", "ca.crt",
                            "--ca-key", "ca.key"));
            assertTrue(failure.getMessage().contains("does not use a CA"), failure.getMessage());
        }

        @Test
        void sharedPasswordOnlyAppliesWhenPrompting() {
            assertThrows(
                    Cli.UsageException.class,
                    () -> parse("--node", "a", "--generate-password", "--shared-password"));
        }

        @Test
        void installingAMultiNodeClusterMustNameTheLocalNode() {
            Cli.UsageException failure = assertThrows(
                    Cli.UsageException.class,
                    () -> parse(
                            "--node", "a", "--node", "b", "--install", "--neo4j-home", "/tmp/neo4j"));
            assertTrue(failure.getMessage().contains("--install-node"), failure.getMessage());
        }

        @Test
        void installingASingleNodeNeedsNoFurtherArgument() throws Exception {
            Options options =
                    parse("--node", "a", "--install", "--neo4j-home", "/tmp/neo4j");
            assertEquals("a", options.installNode().orElseThrow());
        }

        @Test
        void theInstallNodeMustBeOneOfTheNodes() {
            assertThrows(
                    Cli.UsageException.class,
                    () -> parse(
                            "--node", "a",
                            "--install-node", "b",
                            "--neo4j-home", "/tmp/neo4j"));
        }

        @Test
        void installingNeedsAHome() {
            // NEO4J_HOME is not set in the test environment, so this must be reported.
            org.junit.jupiter.api.Assumptions.assumeTrue(System.getenv("NEO4J_HOME") == null);
            Cli.UsageException failure =
                    assertThrows(Cli.UsageException.class, () -> parse("--node", "a", "--install"));
            assertTrue(failure.getMessage().contains("--neo4j-home"), failure.getMessage());
        }
    }

    @Nested
    @DisplayName("configuration files")
    class ConfigFiles {

        @Test
        void supplyTheSameOptionsAsTheCommandLine(@TempDir Path directory) throws Exception {
            Path config = directory.resolve("cluster.properties");
            Files.writeString(
                    config,
                    """
                    # a comment
                    mode=intermediate
                    key-type=rsa-3072
                    validity-days=90
                    organisation=Example Ltd
                    generate-password=true

                    node.core1=core1.example.com,10.0.0.11
                    node.core2=core2.example.com,10.0.0.12
                    """);

            Options options = parse("--config", config.toString());

            assertEquals(TrustMode.INTERMEDIATE, options.trustMode());
            assertEquals(KeyType.RSA_3072, options.keyType());
            assertEquals(90, options.validityDays());
            assertEquals("Example Ltd", options.subject().organisation());
            assertEquals(PasswordProvider.Mode.GENERATE, options.passwordMode());
            assertEquals(List.of("core1", "core2"), options.nodes().stream().map(NodeSpec::name).toList());
        }

        @Test
        void preserveNodeOrder(@TempDir Path directory) throws Exception {
            // Read line by line rather than through Properties, whose hash ordering would make
            // the output non-reproducible.
            StringBuilder text = new StringBuilder();
            for (int i = 1; i <= 12; i++) {
                text.append("node.core").append(i).append("=core").append(i).append(".example.com\n");
            }
            Path config = directory.resolve("cluster.properties");
            Files.writeString(config, text.toString());

            Options options = parse("--config", config.toString());

            for (int i = 1; i <= 12; i++) {
                assertEquals("core" + i, options.nodes().get(i - 1).name());
            }
        }

        @Test
        void areOverriddenByTheCommandLine(@TempDir Path directory) throws Exception {
            Path config = directory.resolve("cluster.properties");
            Files.writeString(config, "mode=self-signed\nvalidity-days=90\nnode.core1=core1.example.com\n");

            Options options = parse("--config", config.toString(), "--mode", "ca");

            assertEquals(TrustMode.CA, options.trustMode(), "the command line wins");
            assertEquals(90, options.validityDays(), "unmentioned settings come from the file");
        }

        @Test
        void nodesFromBothSourcesAccumulate(@TempDir Path directory) throws Exception {
            Path config = directory.resolve("cluster.properties");
            Files.writeString(config, "node.core1=core1.example.com\n");

            Options options = parse("--config", config.toString(), "--node", "core2:core2.example.com");

            assertEquals(List.of("core1", "core2"), options.nodes().stream().map(NodeSpec::name).toList());
        }

        @Test
        void aNodeEntryWithNoValueUsesItsOwnName(@TempDir Path directory) throws Exception {
            Path config = directory.resolve("cluster.properties");
            Files.writeString(config, "node.core1.example.com=\n");

            Options options = parse("--config", config.toString());

            assertEquals(
                    List.of("core1.example.com"), options.nodes().getFirst().subjectAlternativeNames());
        }

        @Test
        void reportTheLineNumberOfAMalformedEntry(@TempDir Path directory) throws Exception {
            Path config = directory.resolve("cluster.properties");
            Files.writeString(config, "mode=ca\nthis is not a setting\n");

            Cli.UsageException failure =
                    assertThrows(Cli.UsageException.class, () -> parse("--config", config.toString()));
            assertTrue(failure.getMessage().contains(":2"), failure.getMessage());
        }

        @Test
        void reportAMissingFile(@TempDir Path directory) {
            Cli.UsageException failure = assertThrows(
                    Cli.UsageException.class,
                    () -> parse("--config", directory.resolve("absent.properties").toString()));
            assertTrue(failure.getMessage().contains("Cannot read"), failure.getMessage());
        }

        @Test
        void cannotNestAnotherConfigFile(@TempDir Path directory) throws Exception {
            Path config = directory.resolve("cluster.properties");
            Files.writeString(config, "config=other.properties\nnode.core1=core1.example.com\n");

            assertThrows(Cli.UsageException.class, () -> parse("--config", config.toString()));
        }
    }
}
