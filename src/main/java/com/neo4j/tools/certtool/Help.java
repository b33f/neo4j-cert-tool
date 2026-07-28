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
              --force                     Overwrite existing files.
              --quiet                     Print only warnings and errors.

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
                        KeyType.names() + " (aliases: " + String.join(", ", KeyType.aliases()) + ")");
    }
}
