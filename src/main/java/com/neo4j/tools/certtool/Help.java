package com.neo4j.tools.certtool;

import com.neo4j.tools.certtool.crypto.Pkcs8;
import com.neo4j.tools.certtool.model.KeyType;
import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.model.TrustMode;

/** The {@code help} output. */
public final class Help {

    private Help() {}

    public static String text() {
        return """
            neo4j-cert-tool - generate TLS certificates for a Neo4j 2025.x cluster

            USAGE
              neo4j-cert-tool [generate] --node <name>[:<san>,...] ... [options]
              neo4j-cert-tool verify --out <dir>
              neo4j-cert-tool update [check] [--pre-releases] [--version <tag>]
              neo4j-cert-tool skill install [self | <skill>] [--all] [--agent <id>] [--refresh]
              neo4j-cert-tool skill list | check | refresh
              neo4j-cert-tool skill remove [<skill>] [--all]
              neo4j-cert-tool help | version

            The tool writes one bundle per cluster member under the output directory:

              out/<node>/certificates/<scope>/private.key   encrypted PKCS#8, mode 0400
              out/<node>/certificates/<scope>/public.crt    PEM certificate (chain), mode 0644
              out/<node>/certificates/<scope>/trusted/      trust anchors, mode 0755
              out/<node>/certificates/<scope>/revoked/       empty, for CRLs, mode 0755
              out/<node>/neo4j.conf.snippet                 settings to merge into neo4j.conf

            Copy each node's certificates directory into that node's NEO4J_HOME, or use
            --install for the machine you are running on. Nothing is written outside the
            output directory unless --install is given.

            CHOOSING A TRUST MODE (--mode)

              ca             (default) One root CA signs a leaf certificate for every node
                             and scope. Each node trusts only the CA certificate.

                             Use this for almost every cluster. Adding or replacing a node
                             later means issuing one new leaf certificate; no existing node
                             has to be touched, because they already trust the CA. Keep
                             out/ca/ off the cluster machines and re-supply it with
                             --ca-cert / --ca-key when you issue for a new node.

              intermediate   Root CA signs an intermediate CA, and the intermediate signs
                             the leaves. Nodes trust the root only.

                             Use this if the root key must stay offline permanently, or if
                             your organisation's PKI policy requires a two-tier hierarchy.
                             It also lets you retire a compromised issuing CA without
                             redistributing trust to every node. Slightly more to manage:
                             public.crt holds leaf + intermediate.

              self-signed    Every node gets a self-signed certificate, and every node's
                             trusted/ directory holds a copy of every node's certificate.

                             Use this only for a single-instance database or a throwaway
                             test cluster. Distribution grows with the square of the
                             cluster size, and adding one node means updating trusted/ on
                             every existing node and restarting them.

              If you are unsure, use the default.

            CLUSTER MEMBERS
              --node <name>[:<san>,...]   A cluster member. Repeatable. <name> is the output
                                          directory name; the comma-separated names after the
                                          colon are the DNS names and IP addresses that peers
                                          will use to reach it. All of them go in the
                                          certificate's subjectAlternativeName, which is what
                                          Neo4j checks when verify_hostname is on (the default
                                          since 2025.01). Omit the colon to use <name> as the
                                          only DNS name.
              --config <file>             Read options from a file. Keys are long option names
                                          without the dashes; cluster members are node.<name>
                                          entries. See EXAMPLES.

            CERTIFICATE CONTENT
              --scopes <list>             Comma-separated SSL policy scopes to populate.
                                          Default: all of them.
              --key-type <type>           Key algorithm. Default: ec-p256.
              --validity-days <n>         Leaf certificate lifetime. Default: 397.
              --ca-validity-days <n>      CA certificate lifetime. Default: 3650.
              --organisation <name>       Subject O attribute. Default: "Neo4j Cluster".
              --organisational-unit <s>   Subject OU attribute.
              --country <cc>              Subject C attribute, two-letter ISO 3166 code.
              --locality <name>           Subject L attribute.
              --state <name>              Subject ST attribute.
              --ca-common-name <name>     Root CA subject CN.
              --intermediate-common-name <name>
                                          Intermediate CA subject CN.

            LIMITING WHAT THE CA CAN ISSUE FOR
              A generated CA is name constrained by default (RFC 5280 nameConstraints,
              marked critical). Without that, anyone holding the CA key could issue a
              certificate for any name at all — google.com included — and every machine
              trusting the CA would believe it. That matters most if you add the CA to an
              operating system trust store.

              The limits are derived from the names you give, widened just enough that the
              CA stays useful:

                DNS   constrained to the parent domain, so a CA made for
                      core1.example.com can later issue core9.example.com but never
                      google.com. A two-label name such as example.com is kept whole,
                      since permitting 'com' would be no constraint at all.
                IP    constrained to the private or loopback range the address is in, so
                      another node on the same network can be added. A routable address is
                      constrained to itself. If no node uses an address at all, every
                      address is excluded.

              The tool refuses to issue for a node outside an existing CA's limits, rather
              than producing certificates that every peer would reject.

              Note where this is and is not enforced. OpenSSL, browsers and the operating
              system trust stores enforce name constraints on a root. The JDK does not:
              path validation begins below the trust anchor, so a root's own constraints
              are skipped. Use --mode intermediate if you need the JDK, and so Neo4j
              itself, to enforce them — an intermediate sits inside the path, where its
              constraints are always processed.

              --permit-dns <suffix>       Also permit this DNS subtree. Repeatable.
              --permit-ip <cidr>          Also permit this address range, for example
                                          10.0.0.0/8. Repeatable.
              --no-name-constraints       Do not constrain the CA at all. Only sensible if
                                          something in your environment mishandles the
                                          extension.

            REUSING AN EXISTING CA
              --ca-cert <file>            Issue from an existing CA certificate instead of
              --ca-key <file>             creating a new one. Use these when adding a node to
                                          a cluster that already trusts a CA from an earlier
                                          run.
              --ca-password-file <file>   Password for that CA key. Prompted for if omitted.

            PRIVATE KEY PROTECTION
              Private keys are always written as encrypted PKCS#8 (PBES2, AES-256-CBC with
              PBKDF2-HMAC-SHA256), which is what Neo4j reads when the matching
              dbms.ssl.policy.<scope>.private_key_password is set.

              By default the tool prompts for a password per node, with echo disabled. A
              password is never accepted as a command line argument, because arguments are
              visible in 'ps' output and are recorded in shell history.

              --generate-password         Generate a strong random password per node and
                                          report it once at the end. Recommended for clusters
                                          and required for unattended runs.
              --password-file <file>      Read passwords from a file: either one password on a
                                          line of its own, or one 'node=password' line per
                                          node. Keep it mode 0600.
              --shared-password           Prompt once and use that password for every key.
              --pbkdf2-iterations <n>     PBKDF2 iterations. Default: %d.

              Note: Neo4j reads private_key_password from neo4j.conf in clear text. The
              password protects the key at rest and while it is being copied to each node; it
              does not protect it from anyone who can read neo4j.conf. Restrict that file to
              the Neo4j service user.

            OUTPUT AND INSTALLATION
              --out <dir>                 Output directory. Default: out.
              --install                   Also copy the generated material into a live
                                          installation, creating certificates/<scope> with the
                                          permissions Neo4j expects.
              --install-node <name>       Which node's bundle to install. Required with
                                          --install when there is more than one node.
              --neo4j-home <dir>          Installation to write into. Defaults to $NEO4J_HOME.
              --owner <user>[:<group>]    Give the generated files this owner, for example
                                          neo4j:neo4j. Needs root, and a POSIX file system.
                                          Without it the tool prints the chown command to run.
              --dry-run                   Report what would be created — every path, with the
                                          permissions it would be given — and write nothing. Also
                                          reports anything that would stop the run, such as a
                                          non-empty output directory, a live policy directory at the
                                          install target, or an unreadable password file or CA.
                                          Exits 0 if the run would proceed and 1 if it would be
                                          blocked, so it can gate a script. No keys are generated
                                          and no password is asked for.
              --force                     Overwrite existing files.
              --quiet                     Print only warnings and errors.
              --no-update-check           Do not run the automatic once-a-day check that
                                          announces a newer release. The check runs only on
                                          interactive generate/verify runs and never downloads
                                          anything; 'update' is unaffected. The environment
                                          variable %s=false switches it off for a machine.

            UPDATING
              update                      Swap the running jar for the latest stable GitHub
                                          release. Only stable v<major>.<minor>.<patch> tags are
                                          considered.
              update check                Report whether a newer release exists and download
                                          nothing. Exits 1 when one does, so a script can gate
                                          on it, and 0 when up to date.
              update --pre-releases       Also consider alpha, beta and rc tags.
              update --version v0.1.0     Move to a named tag. Also the only way to downgrade,
                                          since an unpinned update never goes backwards.

              Only the jar is replaced: the wrapper scripts find it by relative path and carry
              no version of their own. The download is verified against the release's
              SHA256SUMS.txt and swapped in atomically; a mismatch leaves the running jar
              untouched. On Windows the running jar may be locked, in which case the tool
              swaps via a .old file or tells you what to move by hand.

            AGENT SKILLS
              Installs skills that teach AI coding agents how to drive this tool: the embedded
              self-skill (SKILL.md plus per-subcommand references), or any skill from the curated
              catalog at github.com/neo4j-contrib/neo4j-skills.

              skill install                        self-skill into every detected agent
              skill install <skill>                one catalog skill into every detected agent
              skill install --all                  self-skill plus every catalog skill
              skill install --agent <id>           scope any install to one agent (repeatable)
              skill list                           per-(skill × agent) state
              skill check                          drift vs source; exits 1 when drift is found
              skill remove <skill>                 remove one skill
              skill remove --all                   remove every catalog skill (self preserved)
              skill refresh                        force a catalog fetch

              The self-skill is addressable as 'self' (canonical) or by the tool's own name,
              neo4j-cert-tool (alias). Passing an agent name as the positional — for example
              'skill install claude-code' — is a hard error: use --agent instead.

              Supported agents: %s

              Detection is by configuration directory: an agent counts as installed when its
              config directory (for example ~/.claude) exists. With no --agent, every detected
              agent is covered in one go, which also suits multi-agent orchestrators that reuse
              the underlying agents' skill directories.

              The catalog is cached under the user's cache directory with a 24h lifetime; install,
              list and check auto-refresh a stale cache and fall back to the cached copy on
              network failure, with a warning. When the binary version changes, installed
              self-skill bundles are refreshed on the next interactive run — never during a
              non-interactive run, so the skill surface an agent sees never changes mid-task.
              Disable with NEO4J_CERT_TOOL_SKILL_AUTO_REFRESH=false, or refresh explicitly with
              'skill install'.

            VERIFYING
              neo4j-cert-tool verify --out <dir>

              Re-reads a generated directory and checks, for every node and scope, that the
              certificate parses, that the chain validates to a trust anchor in trusted/, that
              the private key matches the certificate, that the extended key usage covers what
              the scope needs, that every declared name is present in the
              subjectAlternativeName, and that file permissions are as restrictive as they
              should be. Prompts for private key passwords, or reads them with
              --password-file.

            EXAMPLES
              A three-node cluster, one CA, generated passwords:

                neo4j-cert-tool \\
                  --node core1:core1.example.com,10.0.0.11 \\
                  --node core2:core2.example.com,10.0.0.12 \\
                  --node core3:core3.example.com,10.0.0.13 \\
                  --generate-password --out ./certs

              A single instance for local development, installed in place:

                neo4j-cert-tool --mode self-signed \\
                  --node localhost:localhost,127.0.0.1,::1 \\
                  --scopes bolt,https --install --neo4j-home /usr/local/neo4j

              Adding a fourth node later, issuing from the CA created above:

                neo4j-cert-tool --node core4:core4.example.com,10.0.0.14 \\
                  --ca-cert ./certs/ca/ca.crt --ca-key ./certs/ca/ca.key \\
                  --generate-password --out ./certs-core4

              The equivalent of the first example as a configuration file:

                # cluster.properties
                mode=ca
                key-type=ec-p256
                validity-days=397
                generate-password=true
                out=./certs
                node.core1=core1.example.com,10.0.0.11
                node.core2=core2.example.com,10.0.0.12
                node.core3=core3.example.com,10.0.0.13

                neo4j-cert-tool --config cluster.properties

            REFERENCE
              Trust modes:   %s
              Scopes:        %s
              Key types:     %s
              Exit codes:    0 success, 1 failure, 2 bad usage
            """
                .formatted(
                        Pkcs8.DEFAULT_ITERATIONS,
                        TrustMode.names(),
                        Scope.names(),
                        KeyType.names() + " (aliases: " + String.join(", ", KeyType.aliases()) + ")",
                        com.neo4j.tools.certtool.skill.AgentRegistry.ids(),
                        com.neo4j.tools.certtool.update.UpdateNotice.ENV_VARIABLE);
    }
}
