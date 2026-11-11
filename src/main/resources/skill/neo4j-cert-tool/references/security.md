# security — the model and its limits

What the tool guarantees, and what it deliberately does not. The full statement lives in
SECURITY.md in the repository; this is the working summary an agent needs.

## Protected

- **Passwords never appear on the command line.** Prompted with echo disabled, generated with a
  secure random generator, or read from a mode-0600 file. Arguments would be visible in `ps` and
  shell history; the tool refuses to accept one.
- **Keys are encrypted at rest** with PBES2 (AES-256-CBC, PBKDF2-HMAC-SHA256 at 600,000
  iterations) and written mode 0400. Permissions are applied when the file is created, so a
  private key is never briefly world-readable.
- **The CA is name-constrained by default** (a critical RFC 5280 nameConstraints extension): a
  leaked CA key cannot mint a certificate for `google.com`.
- **Passwords are handled as zeroed `char[]`** wherever the JVM allows, not interned Strings.
- **The output staging tree is mode 0700** — it holds every node's encrypted keys until they are
  distributed.

## Deliberate limits (documented, not defects)

- **The key password sits in `neo4j.conf` in clear text.** That is how Neo4j reads it. Encrypting
  the key protects it at rest and in transit, not from whoever can read that file.
- **The JDK does not enforce name constraints carried by a trust anchor** — path validation starts
  below it. OpenSSL and OS trust stores do. `--mode intermediate` puts the constraint inside the
  path where the JDK enforces it too.
- **No revocation.** The `revoked/` directories are created for CRLs the operator supplies; the
  tool issues none.
- **The CA key is a password-protected file, not an HSM.** Keeping it off cluster machines is a
  deployment rule the tool warns about, not something it can enforce.
- **Heap hygiene is best-effort.** A moving garbage collector may leave copies behind.
- **Anyone running as the owning user or root can read the material.** The permissions model
  protects against other local users, not privilege escalation.

## Telling the user

For a production deployment the tool's own README recommends certificates from an established CA
issued with long-audited tooling such as OpenSSL. This tool is the right choice when the
deployment wants a self-contained, dependency-free cluster PKI and accepts a small, well-documented
audit surface.
