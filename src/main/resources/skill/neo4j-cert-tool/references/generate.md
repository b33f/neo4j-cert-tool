# generate — reference

    neo4j-cert-tool [generate] --node <name>[:<san>,...] ... [options]

The default command. Writes one bundle per cluster member under `--out` (default `out/`):

    out/<node>/certificates/<scope>/private.key   encrypted PKCS#8, mode 0400
    out/<node>/certificates/<scope>/public.crt    PEM certificate (chain), mode 0644
    out/<node>/certificates/<scope>/trusted/      trust anchors, mode 0755
    out/<node>/certificates/<scope>/revoked/      empty, for CRLs, mode 0755
    out/<node>/neo4j.conf.snippet                 settings to merge into neo4j.conf

Scopes: `bolt`, `https`, `cluster`, `cluster-legacy` — all four by default; trim with
`--scopes bolt,https`.

## Trust modes (`--mode`)

- `ca` (default) — one root CA signs a leaf per node and scope; nodes trust only the CA.
  Right for almost every cluster. Adding a node later issues one leaf; nothing changes on
  existing nodes.
- `intermediate` — root signs an intermediate, intermediate signs leaves; nodes trust the root
  only. Use when the root key must stay offline permanently, when policy requires two tiers, or
  when the JDK (and therefore Neo4j itself) must enforce the CA's name constraints — a root's
  constraints are skipped by JDK path validation, an intermediate's are not.
- `self-signed` — every node self-signs and trusts every other node. Single instances and
  throwaway clusters only.

## Cluster members

    --node core1:core1.example.com,10.0.0.11

The name before the colon is the output directory name; the addresses after it all go into the
certificate's subjectAlternativeName, which is what Neo4j checks when `verify_hostname` is on
(the default since 2025.01). Omit the colon to use the node name as its only DNS name.
Repeat `--node` once per member, or put `node.<name>=<sans>` entries in a `--config` file.

## Key material and naming

- `--key-type` — default `ec-p256`; run `neo4j-cert-tool help` for the full list.
- `--validity-days 397` (leaves, 13 months), `--ca-validity-days 3650` (CA, 10 years).
- `--organisation`, `--organisational-unit`, `--country` (two letters), `--locality`, `--state`,
  `--ca-common-name`, `--intermediate-common-name` — subject attributes.

## Name constraints (on by default)

A generated CA is limited to the names given: DNS names widen to their parent domain, IPs to
their private or loopback range; a public IP constrains to itself, and with no IP nodes every
address is excluded. `--permit-dns <suffix>` and `--permit-ip <cidr>` widen the limits;
`--no-name-constraints` removes them entirely. The tool refuses to issue for a node outside an
existing CA's constraints.

## Reusing an existing CA

    --ca-cert ca.crt --ca-key ca.key [--ca-password-file ca.password]

Issues new leaves from an existing CA so nothing on already-deployed nodes changes. The key may
be encrypted PKCS#8 (prompted for, or read from the password file) or plain.

## Key protection

- `--generate-password` — strong random password per node, printed once at the end. Recommended.
- `--password-file <file>` — one password on a single line, or `subject=password` per line;
  keep it mode 0600. A warning is printed if the file is readable beyond its owner.
- `--shared-password` — prompt once for every key.
- `--pbkdf2-iterations` — default 600000 (OWASP guidance); floor 10000.

Keys are written as PBES2-encrypted PKCS#8 (AES-256-CBC, PBKDF2-HMAC-SHA256), the form Neo4j
reads with `dbms.ssl.policy.<scope>.private_key_password`.

## Output and installation

- `--out <dir>` — bundle root, default `out/`.
- `--install --install-node <name> --neo4j-home <dir>` — additionally write one node's material
  straight into a live installation's `certificates/` directories with the permissions Neo4j
  expects. Refuses non-empty policy directories unless `--force`.
- `--owner neo4j:neo4j` — chown the tree while installing (needs root and POSIX).
- `--dry-run` — print every path, permission and blocker; write nothing; exit 1 if blocked.
- `--force` — overwrite non-empty output directories.

## Exit codes

0 success · 1 failure · 2 bad usage.
