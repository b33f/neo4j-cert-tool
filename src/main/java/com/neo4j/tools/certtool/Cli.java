package com.neo4j.tools.certtool;

import com.neo4j.tools.certtool.model.KeyType;
import com.neo4j.tools.certtool.model.NodeSpec;
import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.model.TrustMode;
import com.neo4j.tools.certtool.skill.AgentRegistry;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * Parses command line arguments, optionally layered on top of a configuration file.
 *
 * <p>Configuration file keys are the long option names without their leading dashes, so anything
 * expressible on the command line can also live in a file. Command line arguments are applied
 * after the file, so they win — except {@code --node}, which accumulates.
 */
public final class Cli {

    /** Thrown for anything the user can fix by changing their arguments. */
    public static final class UsageException extends Exception {
        private static final long serialVersionUID = 1L;

        public UsageException(String message) {
            super(message);
        }
    }

    /** Options that take no value. */
    private static final Set<String> FLAGS = Set.of(
            "install", "generate-password", "shared-password", "dry-run", "no-name-constraints",
            "force", "quiet", "help", "version", "pre-releases", "all", "refresh",
            "no-update-check");

    private Cli() {}

    public static Options parse(String[] args) throws UsageException {
        List<String> arguments = new ArrayList<>(List.of(args));

        // The configuration file is read first so that command line arguments override it. The
        // command word is positional, so it is lifted out and kept at the front: splicing the
        // file's arguments ahead of the user's own must not displace it.
        Optional<Path> configFile = extractConfigFile(arguments);
        List<String> expanded = new ArrayList<>();
        if (!arguments.isEmpty() && !arguments.getFirst().startsWith("-")) {
            expanded.add(arguments.removeFirst());
        }
        if (configFile.isPresent()) {
            expanded.addAll(readConfigFile(configFile.get()));
        }
        expanded.addAll(arguments);

        Draft draft = new Draft();
        int index = 0;

        // A leading bare word selects the command; otherwise the default is to generate.
        if (!expanded.isEmpty() && !expanded.getFirst().startsWith("-")) {
            draft.command = parseCommand(expanded.getFirst());
            index = 1;
        }

        while (index < expanded.size()) {
            String argument = expanded.get(index++);
            if (!argument.startsWith("--")) {
                if (argument.equals("-h")) {
                    draft.command = Options.Command.HELP;
                    continue;
                }
                if (draft.command == Options.Command.UPDATE && argument.equals("check")) {
                    draft.checkOnly = true;
                    continue;
                }
                // The skill command's own grammar: 'skill <action> [<skill-name>]', with bare
                // words carrying the same meaning they would in a dedicated command.
                if (draft.command == Options.Command.SKILL) {
                    if (consumeSkillWord(draft, argument)) {
                        continue;
                    }
                }
                throw new UsageException("Unexpected argument: " + argument);
            }

            String name = argument.substring(2);
            String inlineValue = null;
            int equals = name.indexOf('=');
            if (equals >= 0) {
                inlineValue = name.substring(equals + 1);
                name = name.substring(0, equals);
            }

            // --version is overloaded: bare it selects the version command, with a value it pins
            // an update to a named tag. The pinned value may arrive as --version=v0.1.0 or as
            // the token after --version when the command is update.
            if (name.equals("version") && inlineValue != null) {
                draft.versionPin = inlineValue;
                continue;
            }
            if (name.equals("version")
                    && inlineValue == null
                    && draft.command == Options.Command.UPDATE
                    && index < expanded.size()
                    && !expanded.get(index).startsWith("-")) {
                draft.versionPin = expanded.get(index++);
                continue;
            }

            if (FLAGS.contains(name)) {
                boolean value = inlineValue == null || parseBoolean(name, inlineValue);
                applyFlag(draft, name, value);
                continue;
            }

            String value = inlineValue;
            if (value == null) {
                if (index >= expanded.size()) {
                    throw new UsageException("--" + name + " needs a value");
                }
                value = expanded.get(index++);
            }
            applyOption(draft, name, value);
        }

        return draft.build();
    }

    private static Options.Command parseCommand(String word) throws UsageException {
        return switch (word.toLowerCase(Locale.ROOT)) {
            case "generate" -> Options.Command.GENERATE;
            case "verify" -> Options.Command.VERIFY;
            case "update" -> Options.Command.UPDATE;
            case "skill" -> Options.Command.SKILL;
            case "help" -> Options.Command.HELP;
            case "version" -> Options.Command.VERSION;
            default -> throw new UsageException(
                    "Unknown command '" + word + "'. Expected generate, verify, update, skill, "
                            + "help or version.");
        };
    }

    private static void applyFlag(Draft draft, String name, boolean value) {
        switch (name) {
            case "install" -> draft.install = value;
            case "generate-password" -> {
                if (value) {
                    draft.passwordMode = PasswordProvider.Mode.GENERATE;
                }
            }
            case "shared-password" -> draft.sharedPassword = value;
            case "pre-releases" -> draft.preReleases = value;
            case "all" -> draft.skillAll = value;
            case "refresh" -> draft.refreshCatalog = value;
            case "no-update-check" -> draft.noUpdateCheck = value;
            case "dry-run" -> draft.dryRun = value;
            case "no-name-constraints" -> draft.nameConstraints = !value;
            case "force" -> draft.force = value;
            case "quiet" -> draft.quiet = value;
            case "help" -> draft.command = Options.Command.HELP;
            case "version" -> draft.command = Options.Command.VERSION;
            default -> throw new IllegalStateException("Unhandled flag: " + name);
        }
    }

    private static void applyOption(Draft draft, String name, String value) throws UsageException {
        try {
            switch (name) {
                case "mode" -> draft.trustMode = TrustMode.parse(value);
                case "node" -> draft.nodes.add(NodeSpec.parse(value));
                case "scopes" -> draft.scopes = Scope.parseList(value);
                case "key-type" -> draft.keyType = KeyType.parse(value);
                case "validity-days" -> draft.validityDays = parseDays(name, value);
                case "ca-validity-days" -> draft.caValidityDays = parseDays(name, value);
                case "out" -> draft.outputDirectory = Path.of(value);
                case "install-node" -> {
                    draft.installNode = value;
                    draft.install = true;
                }
                case "neo4j-home" -> draft.neo4jHome = Path.of(value);
                case "owner" -> draft.owner = value;
                case "permit-dns" -> draft.permitDns.add(value.trim());
                case "permit-ip" -> {
                    // Parsed now so a malformed range is a usage error, not a mid-run failure.
                    com.neo4j.tools.certtool.model.NameConstraints.Cidr.parse(value.trim());
                    draft.permitIp.add(value.trim());
                }
                case "organisation", "organization" -> draft.organisation = value;
                case "organisational-unit", "organizational-unit" -> draft.organisationalUnit = value;
                case "country" -> {
                    // Checked here rather than at encoding time, so a typo is a usage error the
                    // user sees immediately instead of a failure part-way through a run.
                    String code = value.trim();
                    if (code.length() != 2 || !code.chars().allMatch(Character::isLetter)) {
                        throw new IllegalArgumentException(
                                "expects a two-letter ISO 3166 code, got '" + value + "'");
                    }
                    draft.country = code;
                }
                case "locality" -> draft.locality = value;
                case "state" -> draft.state = value;
                case "ca-common-name" -> draft.caCommonName = value;
                case "intermediate-common-name" -> draft.intermediateCommonName = value;
                case "ca-cert" -> draft.existingCaCertificate = Path.of(value);
                case "ca-key" -> draft.existingCaKey = Path.of(value);
                case "ca-password-file" -> draft.caPasswordFile = Path.of(value);
                case "password-file" -> {
                    draft.passwordFile = Path.of(value);
                    draft.passwordMode = PasswordProvider.Mode.FILE;
                }
                case "pbkdf2-iterations" -> draft.pbkdf2Iterations = parseIterations(value);
                case "agent" -> {
                    if (com.neo4j.tools.certtool.skill.AgentRegistry.byId(value).isEmpty()) {
                        throw new IllegalArgumentException(
                                "Unknown agent '" + value + "'. Supported: "
                                        + com.neo4j.tools.certtool.skill.AgentRegistry.ids());
                    }
                    draft.agents.add(value);
                }
                case "config" -> throw new UsageException(
                        "--config may not appear inside a configuration file");
                default -> throw new UsageException(
                        "Unknown option --" + name + ". Run 'help' to see the available options.");
            }
        } catch (IllegalArgumentException e) {
            throw new UsageException("--" + name + ": " + e.getMessage());
        }
    }

    /**
     * Consumes a bare word of the skill grammar, when it is one.
     *
     * <p>The first such word selects the action; install and remove then accept one further word
     * naming the skill. Naming an agent positionally is a hard error, since that reads as an
     * instruction to install to a single agent — which is what {@code --agent} is for — and a
     * silent misread would install into the wrong set of agents.
     */
    private static boolean consumeSkillWord(Draft draft, String word) throws UsageException {
        if (draft.skillAction == null) {
            try {
                draft.skillAction = Options.SkillAction.parse(word);
                return true;
            } catch (IllegalArgumentException e) {
                if (AgentRegistry.byId(word).isPresent()) {
                    throw new UsageException(
                            "'" + word
                                    + "' names an agent, not a skill. Use --agent " + word
                                    + " to scope the install, or 'skill install' with no argument"
                                    + " for every detected agent.");
                }
                return false;
            }
        }
        boolean takesASkillName = draft.skillAction == Options.SkillAction.INSTALL
                || draft.skillAction == Options.SkillAction.REMOVE;
        if (takesASkillName && draft.skillName == null) {
            if (AgentRegistry.byId(word).isPresent()) {
                throw new UsageException(
                        "'" + word
                                + "' names an agent, not a skill. Use --agent " + word + ".");
            }
            draft.skillName = word;
            return true;
        }
        return false;
    }

    private static boolean parseBoolean(String name, String value) throws UsageException {
        return switch (value.toLowerCase(Locale.ROOT)) {
            case "true", "yes", "1" -> true;
            case "false", "no", "0" -> false;
            default -> throw new UsageException(
                    "--" + name + " expects true or false, got '" + value + "'");
        };
    }

    private static int parseDays(String name, String value) throws UsageException {
        int days = parseInt(name, value);
        if (days < 1 || days > 7300) {
            throw new UsageException("--" + name + " must be between 1 and 7300 days, got " + days);
        }
        return days;
    }

    private static int parseIterations(String value) throws UsageException {
        int iterations = parseInt("pbkdf2-iterations", value);
        if (iterations < 10_000) {
            throw new UsageException(
                    "--pbkdf2-iterations must be at least 10000 to offer meaningful resistance to "
                            + "offline guessing, got " + iterations);
        }
        return iterations;
    }

    private static int parseInt(String name, String value) throws UsageException {
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw new UsageException("--" + name + " expects a number, got '" + value + "'");
        }
    }

    private static Optional<Path> extractConfigFile(List<String> arguments) throws UsageException {
        for (int i = 0; i < arguments.size(); i++) {
            String argument = arguments.get(i);
            if (argument.equals("--config")) {
                if (i + 1 >= arguments.size()) {
                    throw new UsageException("--config needs a value");
                }
                Path path = Path.of(arguments.get(i + 1));
                arguments.subList(i, i + 2).clear();
                return Optional.of(path);
            }
            if (argument.startsWith("--config=")) {
                Path path = Path.of(argument.substring("--config=".length()));
                arguments.remove(i);
                return Optional.of(path);
            }
        }
        return Optional.empty();
    }

    /**
     * Reads a configuration file into an argument list.
     *
     * <p>Parsed directly rather than through {@link java.util.Properties}, which is backed by a
     * hash table and would lose the node ordering that makes output reproducible.
     */
    static List<String> readConfigFile(Path file) throws UsageException {
        List<String> lines;
        try {
            lines = Files.readAllLines(file, StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UsageException("Cannot read --config file " + file + ": " + e.getMessage());
        }

        List<String> arguments = new ArrayList<>();
        int lineNumber = 0;
        for (String rawLine : lines) {
            lineNumber++;
            String line = rawLine.strip();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) {
                continue;
            }
            int separator = line.indexOf('=');
            if (separator <= 0) {
                throw new UsageException(
                        file + ":" + lineNumber + ": expected 'key=value', found: " + line);
            }
            String key = line.substring(0, separator).strip();
            String value = line.substring(separator + 1).strip();

            if (key.startsWith("node.")) {
                String nodeName = key.substring("node.".length());
                arguments.add("--node");
                arguments.add(value.isEmpty() ? nodeName : nodeName + ":" + value);
            } else if (FLAGS.contains(key)) {
                arguments.add("--" + key + "=" + (value.isEmpty() ? "true" : value));
            } else {
                arguments.add("--" + key);
                arguments.add(value);
            }
        }
        return arguments;
    }

    /** Mutable accumulator, converted to an immutable {@link Options} once every argument is seen. */
    private static final class Draft {
        Options.Command command = Options.Command.GENERATE;
        TrustMode trustMode = TrustMode.CA;
        final List<NodeSpec> nodes = new ArrayList<>();
        Set<Scope> scopes = EnumSet.allOf(Scope.class);
        KeyType keyType = KeyType.EC_P256;
        int validityDays = Options.DEFAULT_VALIDITY_DAYS;
        int caValidityDays = Options.DEFAULT_CA_VALIDITY_DAYS;
        Path outputDirectory = Options.DEFAULT_OUTPUT_DIRECTORY;
        boolean install;
        String installNode;
        Path neo4jHome;
        String owner;
        String organisation = Options.DEFAULT_ORGANISATION;
        String organisationalUnit;
        String country;
        String locality;
        String state;
        String caCommonName = Options.DEFAULT_CA_COMMON_NAME;
        String intermediateCommonName = Options.DEFAULT_INTERMEDIATE_COMMON_NAME;
        Path existingCaCertificate;
        Path existingCaKey;
        Path caPasswordFile;
        PasswordProvider.Mode passwordMode = PasswordProvider.Mode.PROMPT;
        Path passwordFile;
        boolean sharedPassword;
        int pbkdf2Iterations = com.neo4j.tools.certtool.crypto.Pkcs8.DEFAULT_ITERATIONS;
        boolean nameConstraints = true;
        final List<String> permitDns = new ArrayList<>();
        final List<String> permitIp = new ArrayList<>();
        boolean dryRun;
        boolean force;
        boolean quiet;
        boolean checkOnly;
        boolean preReleases;
        String versionPin;
        Options.SkillAction skillAction;
        String skillName;
        boolean skillAll;
        final List<String> agents = new ArrayList<>();
        boolean refreshCatalog;
        boolean noUpdateCheck;

        Options build() throws UsageException {
            if (command == Options.Command.GENERATE) {
                validateForGenerate();
            }
            if (command == Options.Command.UPDATE) {
                validateForUpdate();
            }
            if (command == Options.Command.SKILL) {
                validateForSkill();
            }
            return new Options(
                    command,
                    trustMode,
                    List.copyOf(dedupeNodes()),
                    Set.copyOf(scopes),
                    keyType,
                    validityDays,
                    caValidityDays,
                    outputDirectory,
                    Optional.ofNullable(resolvedInstallNode()),
                    Optional.ofNullable(resolvedNeo4jHome()),
                    new Options.Subject(
                            organisation,
                            organisationalUnit,
                            country,
                            locality,
                            state,
                            caCommonName,
                            intermediateCommonName),
                    passwordMode,
                    Optional.ofNullable(passwordFile),
                    sharedPassword,
                    pbkdf2Iterations,
                    Optional.ofNullable(existingCaCertificate),
                    Optional.ofNullable(existingCaKey),
                    Optional.ofNullable(caPasswordFile),
                    nameConstraints,
                    List.copyOf(permitDns),
                    List.copyOf(permitIp),
                    Optional.ofNullable(owner),
                    dryRun,
                    force,
                    quiet,
                    checkOnly,
                    preReleases,
                    Optional.ofNullable(versionPin),
                    skillAction,
                    Optional.ofNullable(skillName),
                    skillAll,
                    List.copyOf(agents),
                    refreshCatalog,
                    noUpdateCheck);
        }

        private void validateForUpdate() throws UsageException {
            if (noUpdateCheck) {
                throw new UsageException(
                        "--no-update-check suppresses the automatic notice, which 'update' does "
                                + "not run in the first place: update is itself the explicit check");
            }
            if (checkOnly && versionPin != null) {
                throw new UsageException(
                        "--version cannot be combined with 'update check': checking is only "
                                + "defined against the latest release. Use 'update --version "
                                + versionPin + "' to move to that tag.");
            }
            rejectSkillOnlyOptions();
        }

        private void validateForSkill() throws UsageException {
            if (skillAction == null) {
                throw new UsageException(
                        "The skill command needs an action: install, list, check, remove or"
                                + " refresh. For example:  skill install");
            }
            if (skillAll && skillName != null) {
                throw new UsageException(
                        "--all cannot be combined with a named skill: it means '"
                                + skillActionToString() + " every skill'");
            }
            if (skillName != null && skillAction != Options.SkillAction.INSTALL
                    && skillAction != Options.SkillAction.REMOVE) {
                throw new UsageException(
                        "skill " + skillActionToString() + " takes no skill name");
            }
            if (skillAll && skillAction != Options.SkillAction.INSTALL
                    && skillAction != Options.SkillAction.REMOVE) {
                throw new UsageException(
                        "--all applies to 'skill install' and 'skill remove', not to skill "
                                + skillActionToString());
            }
        }

        private String skillActionToString() {
            return skillAction.toString().toLowerCase(java.util.Locale.ROOT);
        }

        private void rejectSkillOnlyOptions() throws UsageException {
            if (skillAction != null || skillAll || refreshCatalog || !agents.isEmpty()) {
                throw new UsageException(
                        "--all, --refresh and --agent only apply to the skill command");
            }
        }

        private List<NodeSpec> dedupeNodes() throws UsageException {
            Set<String> names = new LinkedHashSet<>();
            for (NodeSpec node : nodes) {
                if (!names.add(node.name())) {
                    throw new UsageException("Node '" + node.name() + "' is defined twice");
                }
            }
            return nodes;
        }

        private void validateForGenerate() throws UsageException {
            if (checkOnly || preReleases || versionPin != null) {
                throw new UsageException(
                        "--pre-releases and --version only apply to 'update'; check is its "
                                + "subcommand: 'update check'");
            }
            rejectSkillOnlyOptions();
            if (nodes.isEmpty()) {
                throw new UsageException(
                        """
                        No cluster members were given. Name each one with --node, for example:

                          --node core1:core1.example.com,10.0.0.11 \\
                          --node core2:core2.example.com,10.0.0.12

                        or list them in a file and pass --config cluster.properties.""");
            }
            if ((existingCaCertificate == null) != (existingCaKey == null)) {
                throw new UsageException("--ca-cert and --ca-key must be given together");
            }
            if (existingCaCertificate != null && trustMode == TrustMode.SELF_SIGNED) {
                throw new UsageException(
                        "--mode self-signed does not use a CA, so --ca-cert and --ca-key do not apply");
            }
            if (passwordMode == PasswordProvider.Mode.FILE && passwordFile == null) {
                throw new UsageException("--password-file needs a path");
            }
            if (sharedPassword && passwordMode != PasswordProvider.Mode.PROMPT) {
                throw new UsageException(
                        "--shared-password only applies when prompting for a password");
            }
            if (install && installNode == null && nodes.size() > 1) {
                throw new UsageException(
                        "--install needs --install-node <name> when there is more than one node, "
                                + "because only the local node's material belongs in this NEO4J_HOME");
            }
            if (installNode != null && nodes.stream().noneMatch(n -> n.name().equals(installNode))) {
                throw new UsageException(
                        "--install-node '" + installNode + "' is not one of the --node names");
            }
            if (install && resolvedNeo4jHome() == null) {
                throw new UsageException(
                        "--install needs --neo4j-home <dir>, or the NEO4J_HOME environment variable to be set");
            }
        }

        private String resolvedInstallNode() {
            if (!install) {
                return null;
            }
            return installNode != null ? installNode : nodes.getFirst().name();
        }

        private Path resolvedNeo4jHome() {
            if (neo4jHome != null) {
                return neo4jHome;
            }
            String fromEnvironment = System.getenv("NEO4J_HOME");
            return fromEnvironment == null || fromEnvironment.isBlank()
                    ? null
                    : Path.of(fromEnvironment);
        }
    }
}
