# Security policy

`neo4j-cert-tool` generates private keys and certificate authorities, so a defect in it can have
consequences well beyond the tool itself. Reports are welcome.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's [private vulnerability
reporting](https://github.com/b33f/neo4j-cert-tool/security/advisories/new). That opens a draft
advisory visible only to the maintainers.

A useful report includes:

- the version (`neo4j-cert-tool version`) and the JDK it ran on
- the command line or configuration file used, **with passwords removed**
- what you expected and what happened
- where possible, a certificate or file that demonstrates the problem

Please **never** attach a real private key, a real password, or material from a production cluster.
Generate a fresh example that shows the same behaviour.

You should get an acknowledgement within a few days. Since this is a small project maintained on a
best-effort basis, no fix timeline is promised. Please allow a reasonable period for a fix before
disclosing publicly, and tell us if you intend to disclose on a particular date so the two can be
coordinated.

## What counts as a vulnerability

Anything that causes the tool to produce material weaker than it claims, or to leak material it
should protect. For example:

- a private key written with permissions looser than documented, or readable by another local user
- a key written unencrypted, encrypted with the wrong parameters, or with a weak or reused salt or IV
- a password recoverable from a file, argument list, process listing or log the tool produces
- a certificate whose extensions grant more than intended — a leaf usable as a CA, a missing
  `critical` flag, name constraints that fail to constrain, or a `subjectAlternativeName` covering a
  name that was not asked for
- verification that passes on material which is in fact invalid, mismatched or untrusted
- predictable key material, serial numbers, salts or generated passwords

## What does not

These are known and documented properties, not defects. Please read
[the security section of the README](README.md#security-design-and-its-limits) before reporting one.

- **The private key password is in `neo4j.conf` in clear text.** Neo4j requires it there. Encrypting
  the key protects it at rest and in transit, not from anyone who can read that file.
- **The JDK does not enforce name constraints carried by a trust anchor.** Path validation starts
  below the anchor. OpenSSL and the OS trust stores do enforce them; `--mode intermediate` puts the
  constraint inside the path where the JDK enforces it too. This is
  [documented in full](README.md#where-the-constraint-is-and-is-not-enforced) and pinned by tests.
- **There is no revocation.** `revoked/` is created for you to place CRLs in; the tool neither issues
  nor maintains one.
- **The CA private key is a file protected by a password.** There is no HSM or PKCS#11 support. A CA
  key left on a cluster machine is a deployment mistake the tool warns about, not a flaw in it.
- **Heap hygiene is best-effort.** Passwords are kept in `char[]` and zeroed, but a moving garbage
  collector may leave copies behind. This is defence in depth, not a guarantee.
- **Anyone who can already run as the owning user, or as root, can read the material.** The
  permissions model protects against other local users, not against privilege escalation.

## Supply-chain trust root for `neo4j-cert-tool update`

`update` discovers releases through the GitHub API, downloads the replacement jar from this
repository's GitHub releases, verifies its SHA-256 digest, and swaps it for the running jar. When
you run it, you are extending trust to the following links:

**The JDK's TLS stack against the host root certificate store.** Every HTTPS connection `update`
makes uses the JDK's standard TLS verification against the operating-system root store. If the host
root store is compromised, TLS verification is compromised.

**An explicit four-host allowlist.** `update` will only connect to the following hosts; any
redirect or URL pointing elsewhere is refused before a connection is opened, and a redirect may
never change the scheme:

- api.github.com (release discovery)
- github.com (release assets, including checksum manifests)
- objects.githubusercontent.com
- release-assets.githubusercontent.com

The GitHub hosts serve both the release metadata and the assets — there is no separate metadata
service. These are listed explicitly rather than as a wildcard so that a network operator can
reason precisely about firewall posture.

**Integrity of GitHub release-asset storage for b33f/neo4j-cert-tool.** The jar and its
`SHA256SUMS.txt` manifest are both fetched from GitHub-hosted release storage. Trust in the
published artefacts reduces to trust in GitHub's storage of those assets for this repository.

**SHA256SUMS.txt verified BEFORE the running jar is replaced.** `update` computes the SHA-256 of
the downloaded jar and matches it against the manifest's entry before the swap. A mismatch aborts
the update; no byte of the download ever becomes the running jar, whose permissions the replacement
inherits. The replacement itself is an atomic rename where the file system allows one, so the
jar on disk is always either entirely the old file or entirely the new one.

If all four links hold, the jar that replaces the running one is the jar that was published from
this repository's release workflow.

As an additional, out-of-band check that does not depend on the release assets themselves, every
release asset carries a [build provenance
attestation](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-artifact-attestations)
minted at build time, verifiable with:

    gh attestation verify <file> --repo b33f/neo4j-cert-tool

### Accepted residual risks

The following risks are not mitigated by the current update implementation:

- **Release-workflow compromise.** A malicious change to the release workflow (or to a workflow
  dependency) could publish a tampered jar whose checksum matches a tampered manifest. The checksum
  check does not protect against this. The provenance attestation records how the artefact was
  built, but a compromised workflow can mint one for tampered artefacts too.
- **Release-asset storage compromise.** The jar and the checksum manifest live in the same GitHub
  release storage. An attacker with write access to a published release could replace both files
  coherently.
- **Single-channel substitution.** Because the jar and its checksum manifest travel over the same
  channel, an attacker who can substitute both files at once defeats the checksum check. The
  attestation is the one independent channel: it is verified against GitHub's own attestation
  service, not against the release assets, so it is worth running for a production deployment.

Until these are mitigated, the practical defences are the ones outside `update` itself: verify the
attestation of what you download, pin a known-good version with `update --version <tag>` (an
unpinned update never downgrades), or download and verify releases by hand as [Verifying a
download](README.md#verifying-a-download) describes.

### The skill command's network surface

`skill` has its own, separate trust chain from `update`:

- **The self-skill is embedded.** Its content ships inside the jar, installs into agent skill
  directories, and `skill check` verifies installed copies against digests recomputed from disk —
  no network is involved.
- **The catalog is third-party content.** `skill install <name>`, `skill list`, `skill check` and
  `skill refresh` fetch the curated catalog from `api.github.com` against the
  [neo4j-contrib/neo4j-skills](https://github.com/neo4j-contrib/neo4j-skills) repository — a
  repository this project does not control — and install copies of that content into the detected
  agents' skill directories. The tool itself executes none of what it installs; but an agent that
  loads an installed skill may later read and follow it, which makes every catalog skill a
  prompt-injection surface. Install catalog skills the way you would install any third-party
  instruction material: deliberately, by name, and reviewed if the deployment is sensitive.
- **Cache and fallback.** The catalog is cached under the user's cache directory with a 24-hour
  lifetime; on network failure the cached copy is used with a warning. Cached content is
  overwritten wholesale on each fetch from the same host.

## Supported versions

The most recent release is supported. Fixes are made on `main` and released as a new version rather
than backported.

## Scope

This policy covers the code in this repository. Vulnerabilities in the Neo4j database itself belong
with [Neo4j's security team](https://neo4j.com/security/), and vulnerabilities in the JDK with its
vendor.

## A note on what this tool is for

It is not audited, and it carries no warranty — see [LICENSE](LICENSE), sections 15 and 16. For a
production deployment, obtain certificates from an established certificate authority and generate the
key and signing request with long-audited tooling such as OpenSSL. The README
[explains how](README.md#security-design-and-its-limits).
