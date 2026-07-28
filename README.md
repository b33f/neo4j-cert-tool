# neo4j-cert-tool

Generates TLS certificates for a Neo4j 2025.x or 2026.x cluster, in the layout and format the database
expects, with encrypted private keys and the file permissions Neo4j documents.

Written against **JDK 25 LTS** with **no third-party dependencies at runtime** — X.509 encoding,
key generation, PKCS#8 encryption and filesystem permissions are all done through the JDK. JUnit is
a test-scope dependency only, and the build fails if anything is ever added to the compile or
runtime scope.

Runs on Linux, macOS and Windows.

> Provided without warranty, and not independently audited. For production, prefer certificates from
> a real certificate authority — see [Security design, and its limits](#security-design-and-its-limits).

## Prerequisites

| Tool | Needed for | Version |
| --- | --- | --- |
| JDK | building and running | 25 or later |
| Maven | building only | 3.9 or later |

That is the whole list. The tool has no third-party runtime dependencies, so there is nothing to
install alongside it. Maven downloads JUnit and the build plugins on the first build, which needs
network access once; after that `mvn -o verify` works offline. If someone hands you a built
`neo4j-cert-tool.jar`, you only need the JDK.

The project sets `maven.compiler.release=25`, so a newer JDK builds it fine and the result still runs
on 25 — the class files are version 69 either way. Built and tested on JDK 25.0.4 and 26.0.1.

### macOS

```bash
brew install openjdk@25 maven
```

Homebrew keeps versioned JDKs out of the way ("keg-only"), so link it where macOS looks for JDKs and
point `JAVA_HOME` at it:

```bash
sudo ln -sfn "$(brew --prefix openjdk@25)/libexec/openjdk.jdk" \
  /Library/Java/JavaVirtualMachines/openjdk-25.jdk
export JAVA_HOME=$(/usr/libexec/java_home -v 25)
```

Add the `export` to `~/.zshrc` to make it stick. Without the symlink, `/usr/libexec/java_home` — and
so anything relying on it — will not see the JDK at all.

### Linux

**Ubuntu / Debian.** `openjdk-25-jdk` is in the archive for 22.04 and later, and is the default JDK
from 26.04:

```bash
sudo apt update
sudo apt install openjdk-25-jdk maven
```

**Fedora / RHEL / Rocky / Alma.** Package names track the version, so check what your release
carries before installing:

```bash
dnf search openjdk | grep 25
sudo dnf install java-25-openjdk-devel maven
```

**Any distribution whose packaged JDK is too old.** The Eclipse Adoptium repository carries every
LTS, including 25:

```bash
# Debian / Ubuntu
sudo apt install -y wget apt-transport-https gpg
wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public \
  | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/adoptium.gpg > /dev/null
echo "deb https://packages.adoptium.net/artifactory/deb $(awk -F= '/^VERSION_CODENAME/{print$2}' /etc/os-release) main" \
  | sudo tee /etc/apt/sources.list.d/adoptium.list
sudo apt update
sudo apt install temurin-25-jdk
```

```bash
# Fedora / RHEL — note 'sudo tee', not 'sudo cat > file', which would write as your own user
sudo tee /etc/yum.repos.d/adoptium.repo > /dev/null <<EOF
[Adoptium]
name=Adoptium
baseurl=https://packages.adoptium.net/artifactory/rpm/$(. /etc/os-release; echo $ID)/\$releasever/\$basearch
enabled=1
gpgcheck=1
gpgkey=https://packages.adoptium.net/artifactory/api/gpg/key/public
EOF
sudo dnf install temurin-25-jdk
```

With more than one JDK installed, choose the default with `sudo update-alternatives --config java`
(Debian, Ubuntu) or `sudo alternatives --config java` (Fedora, RHEL). Maven uses `JAVA_HOME` when it
is set, and otherwise whatever `java` resolves to.

### Windows

The JDK is in the winget catalogue:

```powershell
winget install EclipseAdoptium.Temurin.25.JDK
```

The Temurin installer can set `JAVA_HOME` for you if you enable that feature during setup. To set it
afterwards, find the install directory first, since it includes the patch version:

```powershell
Get-ChildItem "C:\Program Files\Eclipse Adoptium"
setx JAVA_HOME "C:\Program Files\Eclipse Adoptium\jdk-25.x.y.z-hotspot"
```

Maven is **not** in the official winget catalogue, so use Chocolatey or Scoop:

```powershell
choco install maven
# or
scoop install maven
```

Failing that, install it by hand: download the binary zip from
[maven.apache.org](https://maven.apache.org/download.cgi), extract it, and add its `bin` directory to
`PATH`. Open a new terminal afterwards so the environment changes take effect.

### Alternative: SDKMAN (macOS, Linux, WSL)

[SDKMAN](https://sdkman.io) manages several JDKs side by side without touching system packages —
handy if you need to keep an older JDK for other work. It needs a POSIX shell, so on Windows it
works under WSL or Git Bash rather than in `cmd` or PowerShell:

```bash
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk list java | grep tem     # find the current Temurin 25 build
sdk install java 25.0.4-tem  # patch versions move; use what the list shows
sdk install maven
```

### Check the toolchain

```bash
java -version
mvn -v
```

`mvn -v` is the one that matters. It prints the JDK Maven has actually picked — `JAVA_HOME` if set,
which may differ from whatever `java` on your `PATH` resolves to. If it reports Java 24 or older the
build fails at `--release 25`, with an error about the release version rather than anything about
this project.

Then prove the whole toolchain works. This compiles the tool and runs the full test suite:

```bash
mvn verify
```

## Build

```bash
mvn package
```

Produces the runnable jar at `bin/neo4j-cert-tool.jar`. Intermediate build output stays in
`target/`; `bin/` holds only the finished jar, and `mvn clean` removes it. Both directories are
gitignored.

Building with a JDK newer than 25 is fine — `maven.compiler.release=25` compiles against the JDK 25
API, so the result runs on any JDK 25 or later.

## Running it

Use the wrapper script for your platform:

```bash
./scripts/neo4j-cert-tool help          # Linux, macOS
scripts\neo4j-cert-tool.cmd help        # Windows
```

The wrappers exist so you do not have to remember where the jar is or which JDK is on your `PATH`.
Each one:

- **finds the jar relative to itself**, so the script works from any working directory — useful for
  cron jobs, CI steps and `sudo` invocations, where the current directory is rarely the repo. If the
  jar is missing it says so and tells you to run `mvn package`, rather than failing with a Java
  stack trace. The POSIX wrapper resolves symlinks first, so linking it onto your `PATH` works.
- **picks the Java runtime** from `JAVA_HOME` if it is set, otherwise from `PATH`.
- **checks the runtime is JDK 25 or later** (POSIX wrapper). Without that check an older JDK fails
  with an `UnsupportedClassVersionError`, which tells you nothing about what to do; the wrapper says
  which Java it found and what is needed instead.
- **passes arguments through untouched** and **preserves the exit code** — `0` success, `1` failure,
  `2` bad usage — so scripting around it behaves as expected.

They are thin by design: no environment is configured and no defaults are injected, so anything the
wrapper can do you can also do directly. If you would rather skip them entirely:

```bash
java -jar bin/neo4j-cert-tool.jar help
```

To run it from anywhere without the relative path, put the wrapper on your `PATH` — a symlink is
fine, since it resolves the jar from its own location:

```bash
sudo ln -s "$PWD/scripts/neo4j-cert-tool" /usr/local/bin/neo4j-cert-tool
```

## Quick start

A three-node cluster with a local CA and generated key passwords:

```bash
./scripts/neo4j-cert-tool \
  --node core1:core1.example.com,10.0.0.11 \
  --node core2:core2.example.com,10.0.0.12 \
  --node core3:core3.example.com,10.0.0.13 \
  --generate-password --out ./certs
```

This writes, for each node:

```
certs/<node>/certificates/<scope>/private.key   encrypted PKCS#8, mode 0400
certs/<node>/certificates/<scope>/public.crt    PEM certificate chain, mode 0644
certs/<node>/certificates/<scope>/trusted/      trust anchors, mode 0755
certs/<node>/certificates/<scope>/revoked/      empty, for CRLs, mode 0755
certs/<node>/neo4j.conf.snippet                 settings to merge, mode 0400
certs/ca/                                       the CA — move this off the machine
```

where `<scope>` is each of `bolt`, `https`, `cluster` and `backup`. The staging root is mode `0700`,
because until the bundles are distributed it holds every node's private keys.

Then, per node:

```bash
rsync -a certs/core1/certificates/ core1.example.com:/var/lib/neo4j/certificates/
ssh core1.example.com 'chown -R neo4j:neo4j /var/lib/neo4j/certificates'
# merge certs/core1/neo4j.conf.snippet into /var/lib/neo4j/conf/neo4j.conf, then restart
```

Or, on the machine you are running on, let the tool do it:

```bash
./scripts/neo4j-cert-tool --node core1:core1.example.com,10.0.0.11 \
  --generate-password --install --neo4j-home /var/lib/neo4j --owner neo4j:neo4j
```

Confirm the result at any point:

```bash
./scripts/neo4j-cert-tool verify --out ./certs
```

`help` documents every option. Run it first — it includes guidance on choosing a trust mode, which
is the one decision worth thinking about.

## Trust modes

| `--mode` | What it builds | When to use it |
| --- | --- | --- |
| `ca` (default) | One root CA signs a leaf certificate per node and scope. Each node trusts only the CA. | Almost every cluster. Adding a node later means issuing one certificate; no existing node is touched. |
| `intermediate` | Root CA → intermediate CA → leaves. Nodes trust the root; the intermediate travels in `public.crt`. | The root must stay permanently offline, or policy requires a two-tier hierarchy. |
| `self-signed` | A self-signed certificate per node, with every node's certificate in every other node's `trusted/`. | A single instance or a throwaway test cluster only. Distribution grows with the square of the cluster size. |

To add a node to an existing `ca` cluster, bring the CA back and issue for the new node alone:

```bash
./scripts/neo4j-cert-tool --node core4:core4.example.com,10.0.0.14 \
  --ca-cert ./certs/ca/ca.crt --ca-key ./certs/ca/ca.key \
  --generate-password --out ./certs-core4
```

The new node's `trusted/root-ca.crt` is byte-identical to what the existing members already hold, so
nothing on them changes.

## What the certificates contain

Matched to what Neo4j 2025.x requires:

- **X.509 v3, PEM encoded.** Private keys are PKCS#8, never the PKCS#1 form Neo4j deprecates.
- **`subjectAlternativeName`** holds every DNS name and IP address given for the node. Neo4j turns
  `verify_hostname` on by default from 2025.01, and modern TLS stacks ignore the common name
  entirely, so anything a peer might connect to has to be listed.
- **`extendedKeyUsage`** is `serverAuth` for `bolt` and `https`; `serverAuth` *and* `clientAuth` for
  `cluster` and `backup`, which default to `client_auth=REQUIRE` and so present the certificate in
  both directions.
- **`basicConstraints`** is critical and marks leaves as non-CA. The root CA carries
  `pathLenConstraint=0` (or `1` in `intermediate` mode) so it cannot be used to mint a CA.
- **`keyUsage`** is critical: `digitalSignature` for EC, plus `keyEncipherment` for RSA so TLS 1.2
  RSA key transport still works.
- **Separate key pair per node per scope**, so a key compromised on one channel does not extend to
  the others.
- **Random 128-bit serial numbers**, and `notBefore` backdated five minutes to absorb clock skew.
- **SHA-256 or better** signatures, paired to the key strength (P-384 keys get SHA-384).

Default leaf lifetime is 397 days and the CA's is 10 years; both are configurable.

## Private key protection

Keys are always written as encrypted PKCS#8: **PBES2** with **AES-256-CBC** and
**PBKDF2-HMAC-SHA256** at 600,000 iterations, which is inside the set Neo4j documents as supported
and is what OpenSSL produces for `-v2 aes-256-cbc -v2prf hmacWithSHA256`. Each key gets a fresh
16-byte salt and IV.

Passwords come from one of three places, and never from a command line argument — arguments are
visible in `ps` output and recorded in shell history:

- **Prompt** (default): no-echo prompt with confirmation, once per node. `--shared-password` prompts
  once for everything.
- `--generate-password`: a random 192-bit password per node, reported once at the end. Use this for
  clusters and for unattended runs.
- `--password-file <path>`: either a single password on its own line, or one `node=password` line
  per node. The tool warns if the file is readable beyond its owner.

Each node's four scope keys share that node's password; different nodes get different passwords, so
a leak on one host does not expose the others.

> **Know what this protects.** Neo4j reads `dbms.ssl.policy.<scope>.private_key_password` from
> `neo4j.conf` in **clear text**. Encrypting the key protects it at rest and while it is being
> copied to each node. It does **not** protect it from anyone who can read `neo4j.conf`. Restrict
> that file to the Neo4j service user:
>
> ```bash
> chown neo4j:neo4j conf/neo4j.conf && chmod 640 conf/neo4j.conf
> ```
>
> The generated `neo4j.conf.snippet` contains the password too, which is why it is written `0400`.

## File permissions

Set at creation time, not applied afterwards, so a private key is never briefly world-readable.
An existing file in the way is removed rather than truncated, so a stale symlink cannot redirect a
key somewhere unprotected.

| Path | Mode |
| --- | --- |
| `certificates/<scope>/` | `0755` |
| `certificates/<scope>/public.crt` | `0644` |
| `certificates/<scope>/private.key` | `0400` |
| `certificates/<scope>/trusted/`, `revoked/` | `0755` |
| staging root, per-node and CA directories | `0700` |
| `neo4j.conf.snippet`, `ca/ca.key` | `0400` |

This matches the table in Neo4j's SSL framework documentation. Ownership is the caller's to set;
`--owner neo4j:neo4j` does it when running as root, and otherwise the tool prints the `chown`
command.

On Windows, where there are no POSIX mode bits, anything that would be owner-only instead gets an
explicit ACL granting the owner alone, which also stops inherited entries from applying.

## Security design, and its limits

> ### No warranty, and when not to use this
>
> This tool is distributed under the GNU GPL v3, which **disclaims all warranty** — see sections 15
> and 16 of [LICENSE](LICENSE). It is written carefully, tested thoroughly, and designed to be as
> secure as it can be. It has **not** been independently audited or formally reviewed by anyone.
>
> **For a production deployment, get your certificates from a real certificate authority.** An
> established CA — your organisation's internal PKI, or a public CA for anything client-facing —
> brings key management, hardware protection, revocation, expiry monitoring and an audit trail that
> a single-purpose tool cannot. The usual route is to generate the key and a certificate signing
> request locally with a dedicated, long-audited tool such as OpenSSL, and send only the CSR away to
> be signed:
>
> ```bash
> # A key and a CSR carrying the names and usages Neo4j needs
> openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
>   -keyout private.key -out core1.csr -noenc \
>   -subj "/O=Example Ltd/CN=core1.example.com" \
>   -addext "subjectAltName=DNS:core1.example.com,IP:10.0.0.11" \
>   -addext "extendedKeyUsage=serverAuth,clientAuth"
>
> # Then protect the key in the same format Neo4j reads
> openssl pkcs8 -topk8 -in private.key -out private.key.enc \
>   -v2 aes-256-cbc -v2prf hmacWithSHA256
> ```
>
> Put the signed certificate in `public.crt`, the issuing CA's certificate in `trusted/`, and the
> encrypted key in `private.key`. The layout and permissions this tool produces are the same either
> way, so `neo4j-cert-tool verify` still checks that result.
>
> Where this tool is a reasonable fit: development and test clusters, internal clusters whose trust
> is genuinely private to the cluster, and getting a working TLS configuration quickly so that the
> rest of a deployment can be tested. It cannot sign a CSR produced elsewhere, and it cannot produce
> one.

### What uses the JDK, and what does not

Every cryptographic primitive is the JDK's. Nothing cryptographic is reimplemented here — no
cipher, no hash, no key derivation, no random number generator.

| Concern | Implementation |
| --- | --- |
| Key pair generation, EC and RSA | JDK `KeyPairGenerator` |
| All randomness — keys, serial numbers, salts, IVs, generated passwords | JDK `SecureRandom` |
| Certificate signing and signature verification | JDK `Signature` (ECDSA, RSA with SHA-256/384/512) |
| Private key encryption, PBES2 | JDK `SecretKeyFactory` and `Cipher` (`PBEWithHmacSHA256AndAES_256`) |
| Private key decryption | JDK `EncryptedPrivateKeyInfo`, `SecretKeyFactory`, `KeyFactory` |
| Certificate parsing, chain validation | JDK `CertificateFactory`, `CertPathValidator` (PKIX) |
| Key identifier digest | JDK `MessageDigest` |
| Base64 | JDK `java.util.Base64` |
| File permissions and ACLs | JDK `Files`, `PosixFilePermissions`, `AclFileAttributeView` |
| TLS handshakes in the test suite | JDK `SSLContext`, `KeyManagerFactory`, `TrustManagerFactory` |

What *is* written by hand is **serialisation, not cryptography** — the ASN.1/DER encoding and the
X.509 structure that wraps the JDK's output:

| Written here | Why |
| --- | --- |
| DER encoder and a minimal reader (`Der`) | The JDK has no public ASN.1 API |
| X.509 v3 certificate assembly (`X509Builder`) | The JDK has no public certificate builder; `sun.security.x509` is internal and would need `--add-exports` |
| Extension encoding (`Extensions`) — basicConstraints, keyUsage, extendedKeyUsage, subjectAltName, subject and authority key identifiers | Same reason |
| Distinguished name encoding (`DistinguishedName`) | Same reason |
| PEM framing (`Pem`) — labels and line wrapping around JDK Base64 | JDK 25's `PEMEncoder` is a preview API and would force `--enable-preview` on every user |
| The `EncryptedPrivateKeyInfo` envelope (`Pkcs8`) | The JDK's own constructor silently drops the PBKDF2 PRF, producing a key nothing can decrypt. The ciphertext, salt, IV and derived key are all still the JDK's; only the ASN.1 wrapper around them is ours |

**Where the risk actually sits.** A mistake in the hand-written code usually fails loudly: a
malformed certificate will not parse, and a broken chain will not validate. Every certificate is
handed back through the JDK's `CertificateFactory` as it is built, and every run re-reads its own
output from disk and checks it — CA-issued chains through the JDK's `CertPathValidator`, self-signed
certificates by verifying their own signature and their presence in `trusted/`. Structural errors
therefore surface at generation time rather than at the far end of a handshake.

The exception worth naming is **extension content**. A wrong `keyUsage` bit, a missing `critical`
flag, or a `basicConstraints` that failed to mark a leaf as a non-CA would be a security defect
rather than a parse error, and would not necessarily be loud — a certificate can be perfectly valid
and still grant more than it should. That is why those specific fields carry the heaviest test
coverage, asserted for every scope individually. The test suite does not shell out to OpenSSL;
generated certificates were cross-checked by hand with `openssl x509 -text` and `openssl verify`
during development, and repeating that after any change to the extension code is worthwhile.

### Design decisions that matter

- **No third-party runtime dependencies at all**, enforced at build time by a banned-dependencies
  rule. The supply chain for the shipped artifact is the JDK and nothing else.
- **Private keys are encrypted at rest** with PBES2: PBKDF2-HMAC-SHA256 at 600,000 iterations,
  AES-256-CBC, a fresh 16-byte salt and IV per key. Two keys never share salt or IV, so identical
  keys or passwords are not detectable by comparing files.
- **Passwords never appear as command line arguments**, because arguments are visible to every user
  on the machine through `ps` and are written to shell history.
- **Passwords are never held in a `String`.** A `String` is immutable and cannot be cleared, so one
  containing a password stays on the heap until the garbage collector happens to reclaim it. Every
  path avoids one: password files are read as bytes and decoded into `char[]` by hand rather than via
  `Files.readAllLines`; generated passwords are base64-encoded to bytes rather than through
  `encodeToString`; the run summary prints the `char[]` directly; and `neo4j.conf.snippet` is
  streamed to disk so the password is never assembled into a buffer first. Arrays are zeroed as soon
  as they are no longer needed, and `PBEKeySpec.clearPassword()` is called so the copy the JDK takes
  during key derivation is cleared too.

  This is defence in depth, not a guarantee. A moving garbage collector may leave copies of an array
  behind, and the dominant exposure is not the heap at all — it is that `neo4j.conf` holds the
  password in clear text because Neo4j requires it there.
- **One key pair per node per scope.** A key compromised on one channel does not extend to the
  others, and a single node's compromise does not implicate its peers.
- **Permissions are set at creation, not afterwards**, so a private key never exists on disk in a
  world-readable state, not even briefly. An existing file in the way is deleted rather than
  truncated, so a symlink cannot redirect a key to somewhere unprotected. POSIX is the primary
  target; on Windows, restriction is done by setting an explicit owner-only ACL, which also stops
  inherited permissions from applying.
- **The staging directory is `0700`** because, until the bundles are distributed, it holds the
  private key of every node in the cluster.
- **The CA key is never needed on a cluster member** and the tool says so, in the run summary and in
  a `README.txt` beside the key.
- **128-bit random serial numbers**, and SHA-256 or stronger signatures throughout. SHA-1 appears in
  exactly one place — deriving key identifiers, RFC 5280's naming function for chain building — where
  it is not relied on for collision resistance.

### What this tool does not do

- **No revocation.** `revoked/` is created empty for you to place CRLs in; the tool neither issues
  nor maintains one. Withdrawing a node's access means re-issuing and redistributing.
- **No key backup, escrow or recovery.** Lose a generated password and that key is unrecoverable.
- **No hardware protection.** The CA private key is a file guarded by a password. There is no
  PKCS#11 or HSM support, which is one of the clearest reasons to prefer a real CA.
- **No CSR handling** in either direction, and no OCSP, certificate transparency, or automated
  renewal.
- **It cannot protect the key password from anyone who can read `neo4j.conf`**, because Neo4j
  requires that password in clear text. See [Private key protection](#private-key-protection).
- **A locally generated root CA is a high-value secret.** Anything holding it can mint a certificate
  every cluster member will trust. That is inherent to the trust model, not a flaw in the tool, and
  it is the main reason `intermediate` mode exists.

## Verifying

`verify` re-reads a generated directory — or a live `NEO4J_HOME` — and checks, per node and scope,
that the certificate parses and is in date, that the chain validates to a trust anchor in
`trusted/`, that the private key decrypts and belongs to the certificate, that the extended key
usage covers what the scope needs, that the `subjectAlternativeName` is populated and covers the
common name, that the key is strong enough and the signature digest acceptable, and that
`private.key` is not readable beyond its owner.

The same checks run automatically at the end of every `generate` run. If they fail, the tool exits
non-zero and tells you not to distribute the output.

Exit codes: `0` success, `1` failure, `2` bad usage.

## Tests

```bash
mvn verify
```

200 tests. Alongside the unit tests for the DER encoder, PEM handling, key encryption and argument
parsing, the suite:

- **completes real TLS handshakes** over loopback using the generated files, loading them the way
  Neo4j does — encrypted key plus password, chain from `public.crt`, trust from `trusted/` — with
  hostname verification enabled and `client_auth` required for the cluster scope. It checks that
  members authenticate each other, that a driver with no client certificate can still reach `bolt`,
  that every listed SAN passes, and that a name absent from the SAN, a certificate from another CA,
  and an outsider trying to join the cluster are all rejected.
- **asserts the exact permissions** of every generated file, that keys are created with their final
  mode, and that a symlink in the way is replaced rather than followed.
- **checks the encryption parameters at the ASN.1 level**, including that the PBKDF2 PRF really is
  HMAC-SHA256. (An earlier version silently downgraded it to HMAC-SHA1 — see below.)
- **runs whole invocations** and asserts on exit codes and output: adding a node from a reused CA,
  installing into a `NEO4J_HOME`, refusing to clobber a live installation, and detecting tampered,
  untrusted or badly permissioned material.

Two notes on JDK behaviour the tests pin down:

- `EncryptedPrivateKeyInfo(AlgorithmParameters, byte[])` cannot be used to write a PBES2 key. It
  maps the parameters through a generic `PBES2` implementation that drops the PRF, so the file
  decodes as PBKDF2's default HMAC-SHA1 and cannot be decrypted by anything — including OpenSSL.
  `Pkcs8` wraps the cipher's untouched parameter encoding instead.
- `PEMEncoder`/`PEMDecoder` (JEP 470) are preview APIs in JDK 25, which would force
  `--enable-preview` on every user at both compile and run time. PEM is a base64 body between two
  label lines, so `Pem` writes it directly.

## Continuous integration and releases

Two GitHub Actions workflows, both in `.github/workflows/`.

**CI** (`ci.yml`) runs on every push to `main`, every pull request, and on demand. It builds and runs
the full test suite across six combinations — Linux, macOS and Windows against JDK 25 and 26 — and
then generates and verifies a real bundle on each runner. That last step matters: the POSIX
permission assertions skip themselves on Windows, so without it the owner-only ACL fallback would
never be exercised anywhere.

**Release** (`release.yml`) runs when you push a tag matching `v*`. It calls the CI workflow first
and publishes nothing unless all six legs pass.

### Cutting a release

The version in `pom.xml` is the single source of truth, and the tag must agree with it. So:

```bash
# 1. bump the version, commit it
mvn versions:set -DnewVersion=1.1.0 -DgenerateBackupPoms=false
git commit -am "Release 1.1.0"

# 2. tag that commit and push
git tag v1.1.0
git push origin main v1.1.0
```

If the tag and `pom.xml` disagree the release fails immediately with a message saying so, rather
than publishing a jar whose `version` command reports something else. A tag with a suffix —
`v1.1.0-rc1` — is published as a prerelease automatically.

To re-run a release for a tag that already exists, use the workflow's manual trigger and give it the
tag name.

### What a release contains

| Asset | Contents |
| --- | --- |
| `neo4j-cert-tool-<version>.jar` | the runnable jar on its own |
| `neo4j-cert-tool-<version>.zip` | jar plus both wrapper scripts, laid out as the wrappers expect, with README and LICENSE |
| `SHA256SUMS.txt` | checksums for both |

Release notes are generated from the commits since the previous tag.

### Verifying a download

Check the checksum:

```bash
sha256sum -c SHA256SUMS.txt
```

Every release asset also carries a signed build provenance attestation, which proves it was built by
this repository's workflow from a specific commit rather than uploaded by hand:

```bash
gh attestation verify neo4j-cert-tool-1.1.0.jar --repo <owner>/neo4j-cert-tool
```

Releases are built with `-Dproject.build.outputTimestamp` set to the tagged commit's date, so the jar
is byte-for-byte reproducible: rebuilding the same tag with the same JDK and Maven version yields an
identical checksum. Differing JDK or Maven versions may still produce a different jar.

## Layout

```
.github/workflows/ci.yml      build and test matrix
.github/workflows/release.yml tag-driven versioned release
scripts/neo4j-cert-tool     wrapper for Linux and macOS
scripts/neo4j-cert-tool.cmd wrapper for Windows
bin/neo4j-cert-tool.jar     the built tool (generated, gitignored)

src/main/java/com/neo4j/tools/certtool/
  Main.java                 entry point, exit codes, run summary
  Cli.java, Options.java    argument and configuration file parsing
  Help.java                 help text, including trust mode guidance
  PasswordProvider.java     prompt / file / generate, zeroed on close
  CertificateGenerator.java issues the CA and per-node certificates
  crypto/                   Der, X509Builder, Extensions, DistinguishedName,
                            Pem, Pkcs8, PemFiles, Oids, SignatureAlgorithm
  model/                    Scope, TrustMode, KeyType, NodeSpec
  output/                   FilePermissions, Layout, BundleWriter, ConfSnippet
  verify/BundleVerifier.java the checks behind `verify` and the self-check
```

## Reference

- [SSL framework](https://neo4j.com/docs/operations-manual/current/security/ssl-framework/) — the
  scopes, settings, directory layout and permission table this tool targets.
