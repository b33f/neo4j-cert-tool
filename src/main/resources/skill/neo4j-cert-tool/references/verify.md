# verify — reference

    neo4j-cert-tool verify --out <dir> [--password-file <file>]

Re-reads a generated directory and checks, for every node and SSL policy scope, that:

- every certificate parses and its chain validates to a trust anchor in `trusted/`
- the private key matches the certificate's public key
- the extended key usage covers what the scope needs
- every declared node name appears in the subjectAlternativeName
- file permissions are as restrictive as the tool documents (private keys 0400, the staging
  tree 0700)

## Reading the output

Each finding is prefixed with its severity. `OK` findings are the passing checks (suppressed with
`--quiet`, which leaves only problems). The final line reports how many of the checks passed.

- **Errors** mean the material is unusable or unsafe: do not distribute it, do not merge the
  `neo4j.conf.snippet`, and regenerate rather than patching files by hand.
- A missing-password error means the directory holds encrypted keys and the password was not
  supplied: pass `--password-file` (same format as generate) or run interactively to prompt.

## When to run it

`generate` already verifies everything it writes before reporting success. Run `verify` again
whenever material has been copied between machines, after changing permissions by hand, and
before restarting a cluster on new certificates. On the target node, verify the installed tree:

    neo4j-cert-tool verify --out <NEO4J_HOME>

## Exit codes

0 all checks passed · 1 at least one check failed.
