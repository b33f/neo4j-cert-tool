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
