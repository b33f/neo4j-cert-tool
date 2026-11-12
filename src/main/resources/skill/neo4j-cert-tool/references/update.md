# update — reference

    neo4j-cert-tool update              # download, verify and swap in the latest stable release
    neo4j-cert-tool update check        # report availability only; exit 1 if a newer release exists
    neo4j-cert-tool update --pre-releases
    neo4j-cert-tool update --version v0.1.0

## Behaviour

- By default only stable `v<major>.<minor>.<patch>` tags are considered. `--pre-releases` also
  considers alpha, beta and rc tags.
- An unpinned update never moves backwards; `--version <tag>` is the only way to downgrade.
- Only the jar is replaced. The wrapper scripts (`scripts/neo4j-cert-tool`,
  `scripts/neo4j-cert-tool.cmd`) locate the jar by relative path and carry no version logic, so
  they survive an update untouched.
- The download is verified against the release's `SHA256SUMS.txt` before anything replaces the
  running jar; a mismatch aborts with the running jar untouched. Connections are restricted to an
  explicit host allowlist (`api.github.com`, `github.com`,
  `objects.githubusercontent.com`, `release-assets.githubusercontent.com`); redirects that point
  anywhere else, or that change the scheme, are refused. See SECURITY.md in the repository for
  the full trust model and its accepted residual risks.
- The swap is an atomic rename where the file system allows one, and the replacement inherits the
  old jar's permissions. On Windows the running jar may be locked; the tool then swaps via a
  `.old` file or prints what to move by hand.

## Agent notes

- `update check` exits 1 when a newer release exists, so a script can gate on it. Exit 0 means
  up to date; exit 2 means bad usage.
- A development build (running from a class directory rather than a jar) can `check` but cannot
  swap: rebuild with `mvn package` instead.
- Every release asset also carries a build-provenance attestation, verifiable with
  `gh attestation verify <file> --repo neo4j-labs/neo4j-cert-tool`.
