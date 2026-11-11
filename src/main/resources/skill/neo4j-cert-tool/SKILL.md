---
name: neo4j-cert-tool
description: Generate and verify TLS certificates (CA, intermediate, self-signed) for Neo4j 2025.x clusters with the neo4j-cert-tool CLI. Use when a user asks for Neo4j TLS setup, cluster certificates, encrypted Bolt/HTTPS configuration, or certificate rotation.
---

# neo4j-cert-tool

Generates a complete TLS certificate bundle for a Neo4j cluster — CA, per-node keys and
certificates for every SSL policy scope, `neo4j.conf` settings — using only the JDK. No OpenSSL
invocations, no third-party dependencies in the tool itself.

## Core workflow

Always follow this order. It is safe to run from the start: nothing is written outside `--out`
unless `--install` is given.

1. **Plan the members.** Every cluster member needs a `--node` argument: a short name and every
   DNS name / IP address peers will use to reach it. Missing addresses are the number one cause
   of `verify_hostname` failures later.
2. **Dry-run first** for anything beyond a trivial cluster: `neo4j-cert-tool --node ... --dry-run`
   prints every path and permission it would create and exits 1 if anything would block. No keys
   are generated and no password is asked for.
3. **Generate** with `--generate-password` (strong random passwords, printed once). Prefer it over
   `--password-file`; never pass passwords as arguments or environment variables.
4. **Verify** what was written: `neo4j-cert-tool verify --out <dir>` — 54+ checks covering chain
   validation, key/certificate matching, SANs, EKU and file permissions. The generate run already
   verifies before reporting success; run `verify` again after you copy bundles around.
5. **Distribute**: copy each `out/<node>/certificates/` directory to that node's `NEO4J_HOME`
   (preserve permissions: `rsync -a` or `scp -rp`), then merge the node's `neo4j.conf.snippet`.
   Restart once to activate. Keep `out/ca/` OFF the cluster machines — it can mint certificates
   every node trusts.

## Safety rules for agents

- Run `--dry-run` before a first generate against a real machine.
- Never place passwords on the command line (visible in `ps` and shell history) or in files
  looser than mode 0600. The tool enforces a 12-character minimum on prompted passwords.
- Never copy the `ca/` directory (or `--ca-key`) onto a cluster machine.
- A CA created by this tool is name-constrained by default: it can only issue for the node names
  given plus their parent domain / private IP ranges. Removing that limit (`--no-name-constraints`)
  requires an explicit reason the user stated.
- The key password ends up in `neo4j.conf` in clear text because that is how Neo4j reads it;
  restrict that file to the Neo4j service user (`chown neo4j:neo4j; chmod 640`).
- The tool reports success only after re-reading and verifying what it wrote. If verification
  fails, treat the output as unusable: do not distribute it.

## Reference

Per-subcommand references live in `references/`:

- `references/generate.md` — every generate option: trust modes, key types, scopes, name
  constraints, reusing an existing CA, installing into a live `NEO4J_HOME`.
- `references/verify.md` — what `verify` checks and how to read its findings.
- `references/update.md` — self-update: `update check` (exit 1 when newer), `--pre-releases`,
  `--version <tag>` pinning, checksum verification.
- `references/security.md` — the security model and its documented limits: what is protected, what
  is deliberately not, and what to tell a user who asks for production hardening.

Version and runtime: `neo4j-cert-tool version`. Full help: `neo4j-cert-tool help`.
