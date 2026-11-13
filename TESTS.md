# Tests

Every test in the suite, grouped by the class that holds it and the feature area it covers.
Run them all with:

    mvn --batch-mode verify

The suite is pure JUnit, needs no network, and stands up local HTTP servers where a test must
impersonate one (the GitHub release feed, the skill catalog). Counts: 343 test methods, 450
executions once parameterized cases are expanded.

The classes cover, in order: certificate content, the command line, dry runs, end-to-end runs,
file permissions, name constraints, password handling, TLS handshakes, the client truststore,
self-update, DER encoding, IP literal parsing, PEM encoding, PKCS#8 encryption, key-generation
strength, signature-algorithm selection, and the agent-skill system.

---

## `CertificateContentTest` — certificate content

What a generated bundle contains, checked by parsing the emitted certificates.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Scope coverage | `everyScopeIsPopulated` | every scope gets a version 3 certificate covering its declared names |
| Extended key usage | `extendedKeyUsageMatchesTheScope` | EKU matches what the scope's `client_auth` default needs |
| Basic constraints | `leavesAreNotCas` | leaf certificates are not CA certificates |
| Key usage | `keyUsageIsCorrect` | key usage is critical and permits digital signatures |
| Key usage (RSA) | `rsaLeavesPermitKeyEncipherment` | RSA leaves additionally permit keyEncipherment |
| Key usage (EC) | `ecLeavesDoNotClaimKeyEncipherment` | EC leaves do not claim keyEncipherment, which they cannot do |
| Chain building | `keyIdentifiersLinkTheChain` | key identifiers link each leaf to its issuer |
| CA restraint | `theCaIsConstrained` | the CA can sign certificates and nothing else |
| CA restraint | `intermediateModeConstrainsBothTiers` | intermediate mode produces a root that may issue one level of CA |
| Self-signed mode | `selfSignedModeCrossTrusts` | self-signed mode cross-trusts every member and creates no CA |
| Trust anchors | `caModeTrustsOnlyTheRoot` | ca mode puts only the root in `trusted/` |
| Key isolation | `keysAreNeverShared` | every node and scope gets its own key pair |
| Serial numbers | `serialNumbersAreRandom` | serial numbers are unpredictable and positive |
| Validity | `validityHonoursTheRequestedLifetime` | validity is backdated slightly and runs for the requested number of days |
| Validity | `caOutlivesItsLeaves` | CA certificates outlive the leaves they issue |
| Signatures | `signaturesUseModernDigests` | certificates are signed with a SHA-2 family digest |
| Subject | `subjectAttributesAreCarriedThrough` | subject naming attributes are carried through |
| Scope selection | `onlyRequestedScopesAreWritten` | only the requested scopes are written |
| IP-only nodes | `ipOnlyNodesAreSupported` | an IP-only node still gets a usable certificate |
| Key/cert pairing | `privateKeysMatchTheirCertificates` | private keys on disk belong to the certificates beside them |
| Key encryption | `keysOnDiskAreEncrypted` | keys on disk are encrypted, not merely stored |
| Distinctness | `nodesAreDistinct` | two nodes' certificates differ even with identical names |
| DER time | `timesAreWholeSeconds` | notBefore is truncated to whole seconds, as DER time requires |

## `CliTest` — command-line parsing

Argument parsing, validation and configuration-file handling.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Defaults | `areTheSafeChoices` | a bare run picks the safe choices for every option |
| Defaults | `matchTheDefaultsRecord` | the parsed defaults match `Options.defaults()` |
| Node specifications | `takeTheirNamesFromTheArgument` | `--node name:sans` yields the node name and SAN list |
| Node specifications | `defaultToTheNodeNameWhenNoNamesAreGiven` | a node with no addresses uses its own name |
| Node specifications | `splitOnTheFirstColonSoIpv6LiteralsSurvive` | IPv6 literals survive the name/address split |
| Node specifications | `areAccumulatedInOrder` | repeated `--node` accumulate in order |
| Node specifications | `lowerCaseDnsNamesButLeaveAddressesAlone` | DNS names are lower-cased; IP addresses are not |
| Node specifications | `deduplicateRepeatedNames` | repeated SAN names are deduplicated |
| Node specifications | `rejectDuplicateNodeNames` | a node named twice is a usage error |
| Node specifications | `rejectNamesThatWouldEscapeTheOutputDirectory` | names with path separators or `..` are rejected |
| Node specifications | `areRequiredForGeneration` | generation without nodes explains what to pass |
| Option syntax | `acceptsSpaceSeparatedAndEqualsForms` | `--opt value` and `--opt=value` both parse |
| Option syntax | `treatsALeadingBareWordAsTheCommand` | a leading bare word selects the command |
| Option syntax | `recognisesHelpAndVersionFlagsAnywhere` | `--help`/`--version` work in any position |
| Option syntax | `reportsAnUnknownOption` | unknown options are usage errors |
| Option syntax | `reportsAnUnknownCommand` | unknown commands list the valid ones |
| Option syntax | `reportsAMissingValue` | an option at the end without a value is reported |
| Option syntax | `reportsAStrayPositionalArgument` | stray positional arguments are rejected |
| Option syntax | `acceptsBothSpellingsOfOrganisation` | `--organisation` and `--organization` both work |
| Value validation | `keyTypesAndTheirAliases` | key type names and aliases resolve |
| Value validation | `anUnknownKeyTypeListsTheValidOnes` | an unknown key type lists the valid ones |
| Value validation | `scopeListsPreserveOrderAndRejectDuplicates` | scope lists preserve order and reject duplicates |
| Value validation | `validityMustBeAReasonableNumberOfDays` | validity days are bounded (1–7300) |
| Value validation | `iterationCountsBelowTheFloorAreRejected` | PBKDF2 below 10,000 iterations is rejected |
| Value validation | `countryMustBeTwoLetters` | `--country` must be a two-letter code |
| Value validation | `aCaCertificateNeedsItsKey` | `--ca-cert` without `--ca-key` is rejected |
| Value validation | `selfSignedModeHasNoCaToReuse` | `--ca-cert`/`--ca-key` with self-signed mode is rejected |
| Value validation | `sharedPasswordOnlyAppliesWhenPrompting` | `--shared-password` with a password file is rejected |
| Value validation | `installingAMultiNodeClusterMustNameTheLocalNode` | `--install` with several nodes needs `--install-node` |
| Value validation | `installingASingleNodeNeedsNoFurtherArgument` | `--install` with one node defaults to it |
| Value validation | `theInstallNodeMustBeOneOfTheNodes` | `--install-node` must name a given node |
| Value validation | `installingNeedsAHome` | `--install` without a home directory is rejected |
| Configuration files | `supplyTheSameOptionsAsTheCommandLine` | a config file supplies the same options as the command line |
| Configuration files | `preserveNodeOrder` | `node.` entries preserve their file order |
| Configuration files | `areOverriddenByTheCommandLine` | command-line arguments override the file |
| Configuration files | `nodesFromBothSourcesAccumulate` | nodes from both sources accumulate |
| Configuration files | `aNodeEntryWithNoValueUsesItsOwnName` | a bare `node.name` entry uses the name as its SAN |
| Configuration files | `reportTheLineNumberOfAMalformedEntry` | a malformed entry reports its line number |
| Configuration files | `reportAMissingFile` | a missing config file is reported clearly |
| Configuration files | `cannotNestAnotherConfigFile` | `--config` inside a config file is rejected |
| Configuration files | `theCommandWordSurvivesAConfigFileSplicedBeforeIt` | regression: the command word is not displaced by the file's arguments |
| Update command | `installsTheLatestStableByDefault` | `update` defaults to install, stable, unpinned |
| Update command | `takesCheckAsASubcommand` | `update check` sets the check-only mode |
| Update command | `checkIsNotAWordAnywhereElse` | `check` is only a word inside `update` |
| Update command | `acceptsThePinInlineAndAsTheNextArgument` | `--version=v0.1.0` and `--version v0.1.0` both pin |
| Update command | `bareVersionIsStillTheVersionCommand` | a bare `--version` still prints the version |
| Update command | `optsIntoPreReleases` | `--pre-releases` is accepted on `update` and `update check` |
| Update command | `refusesToCheckAgainstAPinnedTag` | `--version` cannot combine with `update check` |
| Update command | `updateOnlyOptionsAreRejectedOnAGenerateRun` | update-only options are rejected elsewhere |
| Skill command | `needsAnAction` | bare `skill` demands an action |
| Skill command | `parsesEveryAction` | install, list, check, remove and refresh all parse |
| Skill command | `namesASkillPositionally` | `skill install <name>` takes the skill name positionally |
| Skill command | `scopingToAnAgentIsAFlagNotAPositional` | `--agent` scopes the install; the name stays the skill |
| Skill command | `acceptsRepeatedAgentsAndRejectsUnknownOnes` | `--agent` is repeatable and validated |
| Skill command | `anAgentNameAsThePositionalIsAHardError` | an agent name as the positional is a hard error pointing at `--agent` |
| Skill command | `allMeansEverySkill` | `--all` means every skill |
| Skill command | `allCannotBeCombinedWithANamedSkill` | `--all` with a named skill is rejected |
| Skill command | `allIsRejectedOnActionsThatTakeNoSetOfSkills` | `--all` is rejected on check and refresh |
| Skill command | `agentsMayComeFromAConfigurationFile` | `agent=` entries in a config file supply agents |
| Skill command | `listAndCheckAndRefreshTakeNoSkillName` | list, check and refresh take no positional name |
| Skill command | `forcesACatalogFetchWithRefresh` | `--refresh` forces a catalog fetch |
| Skill command | `skillOptionsAreRejectedOnAGenerateRun` | skill-only options are rejected on generate |
| Update notice | `theAutomaticUpdateCheckCanBeSuppressed` | `--no-update-check` parses, and is rejected on `update` |

## `DryRunTest` — dry runs

What `--dry-run` promises, and whether it keeps the promise.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Safety | `writesNothing` | a dry run writes absolutely nothing |
| Output | `explainsItself` | says plainly that it is a dry run, and what would be produced |
| Output | `reportsPermissions` | lists each path with the permissions it would be given |
| Fidelity | `planMatchesReality` | the plan matches exactly what a real run creates |
| Fidelity | `plannedPermissionsMatchReality` | the planned permissions match the permissions actually applied |
| Blockers | `detectsBlockedOutputDirectory` | detects a non-empty output directory that would block the run |
| Blockers | `forceClearsTheBlocker` | a blocked run reports success once `--force` is added |
| Blockers | `detectsBlockedInstall` | detects an install target that already holds a policy directory |
| Blockers | `detectsMissingPasswordFile` | detects a missing password file |
| Blockers | `detectsMalformedPasswordFile` | detects a malformed password file before a real run would |
| Blockers | `detectsMissingCa` | detects a missing CA when issuing from an existing one |
| Blockers | `reportsAllBlockers` | reports every blocker at once, not just the first |
| Scope selection | `reusingACaPlansNoCaDirectory` | reusing an existing CA plans no new CA directory |
| Scope selection | `respectsScopeSelection` | only the selected scopes appear in the plan |

## `EndToEndTest` — end-to-end behaviour

Whole-process runs: exit codes, generated output, and the verify command catching tampering.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Commands | `helpGuidesTheTrustModeChoice` | help explains how to choose a trust mode |
| Commands | `versionReportsTheRuntime` | version reports the tool and the JVM it is running on |
| Commands | `badUsageIsDistinguishableFromFailure` | bad usage exits 2 and points at help |
| Commands | `missingNodesAreExplained` | a run with no nodes explains what to pass |
| Self-verification | `generationSelfVerifies` | generation self-verifies and reports its checks |
| Verify | `verifyPassesOnGeneratedMaterial` | the verify command passes on freshly generated material |
| Verify | `verifyDetectsAnUntrustedCertificate` | verify fails when a certificate has been swapped for another CA's |
| Verify | `verifyDetectsAnEmptyTrustStore` | verify fails when `trusted/` has been emptied |
| Verify | `verifyDetectsLoosePermissions` | verify fails when a private key has been made group-readable |
| Verify | `verifyDetectsTheWrongPassword` | verify fails with the wrong password |
| Verify | `verifyAcceptsASingleBundle` | verify works against an installed `NEO4J_HOME` too |
| Verify | `verifyReportsAnEmptyDirectory` | verify reports a path with no certificates at all |
| Output protection | `existingOutputIsProtected` | a non-empty output directory is refused unless forced |
| Output protection | `forceOverwrites` | `--force` replaces an existing output directory |
| Passwords | `generatedPasswordsAreReported` | generated passwords are reported once and reach the conf snippet |
| Conf snippet | `theConfSnippetIsComplete` | the conf snippet enables each scope with the right defaults |
| Install | `installWritesIntoNeo4jHome` | `--install` writes into a `NEO4J_HOME` and leaves the staging bundle intact |
| Install | `installDoesNotClobberALiveInstallation` | `--install` refuses to overwrite an existing policy directory |
| CA reuse | `aNodeCanBeAddedLater` | a node can be added later by reusing the CA, without touching existing members |
| CA reuse | `aLeafOnlyCaCannotSignAnIntermediate` | reusing a CA whose pathLenConstraint forbids it is reported clearly |
| CA reuse | `aMismatchedCaIsCaught` | a mismatched CA certificate and key are caught |
| CA directory | `theCaDirectoryExplainsItself` | the CA directory carries instructions for keeping it safe |
| Output control | `quietSuppressesTheSummary` | `--quiet` prints nothing on success except generated secrets |
| Passwords | `perNodePasswordsAreSupported` | a password file may give each node its own password |
| Passwords | `ambiguousPasswordFilesAreRejected` | a password file with conflicting formats is rejected |
| Configuration | `aConfigFileDrivesTheRun` | a config file drives a whole run |

## `FilePermissionsTest` — file permissions

The permissions of everything the tool writes. Skipped where the file system has no POSIX bits.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Key material | `permissionsMatchTheDocumentedTable` | `private.key` is 0400, `public.crt` is 0644, directories are 0755 |
| Staging | `theStagingDirectoryIsPrivate` | the staging directory is 0700, because it holds every node's keys |
| CA key | `theCaKeyIsProtected` | the CA private key is 0400 |
| Conf snippet | `theConfSnippetIsProtected` | the conf snippet is 0400, because it contains the key password |
| Exposure | `onlyPublicMaterialIsWorldReadable` | no generated file is readable by group or others except certificates and the client truststore |
| Creation window | `keysAreCreatedWithTheirFinalPermissions` | a private key is never briefly world-readable while being written |
| Replacement | `existingFilesAreReplacedNotTruncated` | writing over an existing loose file replaces its permissions |
| Symlinks | `symlinksAreNotFollowed` | a symlink in the way is replaced, not followed |
| Presentation | `permissionsAreDescribedReadably` | the permission describer renders both symbolic and octal forms |

## `NameConstraintsTest` — name constraints

What constrains a generated CA, and where the constraint is and is not enforced.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Derivation | `dnsNamesAreConstrainedToTheirParent` | DNS names are constrained to their parent domain |
| Derivation | `oneDomainOneSubtree` | a cluster in one domain yields one subtree |
| Derivation | `subtreesCollapse` | a broader subtree absorbs one beneath it |
| Derivation | `addressesAreConstrainedToTheirBlock` | addresses are constrained to their private/loopback block |
| Derivation | `addressesAreExcludedWhenUnused` | with no addresses at all, every address is excluded |
| Derivation | `extraSubtreesAreHonoured` | `--permit-dns` and `--permit-ip` widen the constraint |
| Derivation | `permitsAnswersCorrectly` | the constraint knows what it permits |
| Extensions | `caIsConstrained` | the CA carries a critical nameConstraints extension |
| Extensions | `intermediateIsConstrained` | the intermediate is constrained too, where a validator will always see it |
| Extensions | `leavesAreNotConstrained` | leaf certificates are not constrained; the limit belongs on the CA |
| Switches | `constraintsCanBeSwitchedOff` | `--no-name-constraints` leaves the CA unconstrained |
| Switches | `selfSignedModeIsUnaffected` | self-signed mode has no CA to constrain |
| Enforcement | `constraintIsEnforcedInsideThePath` | a forged certificate is rejected when the constrained CA is inside the path |
| Enforcement | `anchorConstraintsAreNotEnforcedByTheJdk` | the JDK does not enforce constraints carried by a trust anchor (documented limit) |
| Issuing later | `permittedNodesAreIssued` | a node inside the constraint can still be added later |
| Issuing later | `forbiddenNodesAreRefused` | a node outside the constraint is refused, with the reason |

## `PasswordProviderTest` — password handling

Where passwords come from and how they are protected in memory.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Password files | `aSingleBareLineAppliesToEverySubject` | one bare line is the default password |
| Password files | `windowsLineEndingsAreHandled` | CRLF files parse |
| Password files | `aMissingFinalNewlineIsFine` | a file with no trailing newline still yields its password |
| Password files | `commentsAndBlankLinesAreIgnored` | comments and blank lines are skipped |
| Password files | `whitespaceAroundTheSubjectIsTrimmedButNotInsideThePassword` | surrounding whitespace is trimmed; embedded whitespace survives |
| Password files | `mixingBothFormsIsRejected` | mixing a bare line with `subject=password` lines is rejected |
| Password files | `twoBareLinesAreRejected` | two bare lines are ambiguous and rejected |
| Password files | `anEmptyFileIsRejected` | an empty password file is an error |
| Password files | `anUnknownSubjectWithNoDefaultIsReported` | a node with no entry and no default is reported |
| Password files | `nonAsciiPasswordsSurviveTheRoundTrip` | non-ASCII passwords survive encoding and reading back |
| Password files | `readSingleFromTakesTheFirstRealLine` | the CA password file form takes the first real line |
| Password files | `readSingleFromRejectsAFileWithNothingInIt` | a file with only comments and blanks is rejected |
| Generation | `areLongAndUseOnlyConfigSafeCharacters` | generated passwords are long and paste-safe in `neo4j.conf` |
| Generation | `differPerSubjectAndAreStableWithinOne` | each subject gets its own password, stable within the run |
| Generation | `manyGeneratedPasswordsAreAllDistinct` | a thousand generated passwords are all distinct, so no entropy is truncated away |
| Generation | `generatedPasswordsSpanTheWholeAlphabet` | the full base64url alphabet is exercised, not a subset that would halve the effective entropy |
| Generation | `generationConsumesTheSuppliedRandomness` | generation draws its full 24 bytes from the `SecureRandom` it was given |
| Generation | `areReportedForTheRunSummary` | generated passwords are reported once at the end |
| Generation | `suppliedPasswordsAreNotEchoedBack` | passwords the user supplied are not printed back |
| Warnings | `aShortPasswordWarns` | a password file with short passwords warns that key encryption is only as strong as the password |
| Warnings | `aStrongPasswordDoesNotWarn` | a password file with strong passwords stays quiet |
| Lifecycle | `closingZeroesPasswords` | closing the provider zeroes every password it was holding |
| Lifecycle | `closingZeroesGeneratedPasswords` | a generated password is zeroed on close too |

## `TlsHandshakeTest` — TLS handshakes

Real handshakes between generated endpoints: what the certificates actually do in TLS.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Cluster scope | `clusterMembersAuthenticateEachOther` | two cluster members mutually authenticate |
| Cluster scope | `backupScopeRequiresClientAuthentication` | mutual authentication works for the backup scope too |
| Bolt scope | `boltClientsNeedNoCertificate` | a driver with no client certificate connects |
| Hostname verification | `everySubjectAlternativeNameIsAccepted` | every SAN entry passes hostname verification |
| Hostname verification | `ipOnlyCertificatesWork` | an IP-only certificate verifies when connecting by address |
| Hostname verification | `ipv6OnlyCertificatesWork` | an IPv6-only certificate works too |
| Hostname verification | `anUnlistedAddressIsRejected` | an IP not in the certificate is rejected |
| Hostname verification | `anUnlistedHostnameIsRejected` | a name absent from the SAN is rejected |
| Trust boundaries | `aForeignCertificateIsRejected` | a certificate from a different CA is rejected |
| Trust boundaries | `aForeignClientCannotJoinTheCluster` | a client from a different CA cannot authenticate |
| Trust modes | `intermediateChainValidates` | intermediate mode: the server's chain validates against the root |
| Trust modes | `selfSignedMembersTrustEachOther` | self-signed mode: cross-trusted members authenticate |
| Key types | `rsaKeysAlsoHandshake` | RSA keys work end to end |
| Key types | `p384KeysAlsoHandshake` | P-384 keys work end to end |
| Protocol | `tls13IsNegotiated` | TLS 1.3 is negotiated, so the dropped CBC suites are not needed |

## `TruststoreTest` — the client truststore

The PKCS#12 truststore a run writes at the staging root, which Java clients (cypher-shell, driver
applications) load to trust the cluster.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Trust modes | `caModeTrustsTheRoot` | ca mode's truststore holds exactly the CA certificate |
| Trust modes | `selfSignedTrustsEveryMember` | self-signed mode's truststore holds every member's per-scope certificate, aliased by node and scope |
| Trust modes | `intermediateModeTrustsTheRoot` | intermediate mode's truststore holds the root, as the nodes do |
| CA reuse | `reusingAnExistingCaStillWritesOne` | a run that reuses a CA with `--ca-cert` still writes a truststore anchored at that CA |
| Handshake | `aJavaClientCompletesAHandshakeThroughIt` | a client trusting only the truststore file authenticates a generated server in a real TLS handshake |
| Verify | `verifyChecksIt` | verify reports the truststore loading and covering every anchor the bundles trust |
| Contents safety | `holdsOnlyCertificateEntries` | in every mode, every entry is a trusted certificate entry and no alias yields private or secret key material — the property that makes the well-known `changeit` password safe |
| Verify | `missingIsOnlyAWarning` | a missing truststore warns without failing, so pre-truststore bundles verify clean |
| Verify | `corruptFails` | a truststore that does not load fails verification |
| Verify | `incompleteFails` | a truststore missing an anchor the bundles trust fails verification |

## `UpdateTest` — self-update

`update check` and `update install`, against a local server impersonating the GitHub release feed.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Version ordering | `ordersByComponents` | versions order by numeric components |
| Version ordering | `sortsAReleaseCandidateBelowItsRelease` | 1.3.0-rc1 sorts below 1.3.0 |
| Version ordering | `countsReleaseCandidatesNumerically` | rc10 sorts after rc2 |
| Version ordering | `treatsIdenticalSuffixedVersionsAsEqual` | identical suffixed versions compare equal across tag spellings |
| Version ordering | `sortsTextSuffixesLexically` | alpha sorts before beta |
| Version ordering | `acceptsTheVersionTheJarReportsItself` | both `1.2.1` and `v1.2.1` parse |
| Version ordering | `rejectsTagsThisProjectWouldNotPublish` | non-versions and development builds do not parse |
| Check | `reportsANewerStableRelease` | a newer stable release is reported |
| Check | `reportsUpToDateAtTheLatestStable` | being current is reported as up to date |
| Check | `considersAPreReleaseOnlyWhenAsked` | pre-releases are considered only with `--pre-releases` |
| Check | `reportsTheLatestEvenForADevelopmentBuild` | a development build still reports the latest, without claiming an update is needed |
| Install | `swapsTheJarForTheNewerRelease` | the jar is swapped and the staging file cleaned up |
| Install | `keepsTheOldPermissions` | the replacement inherits the old file's permissions |
| Install | `refusesToSwapADevelopmentBuild` | a development build has no jar to swap and says so |
| Install | `leavesTheRunningJarUntouchedOnAChecksumMismatch` | a bad checksum never touches the running jar |
| Install | `doesNothingWhenAlreadyUpToDate` | an up-to-date install does nothing |
| Install | `downgradesOnlyWhenPinned` | a pinned tag installs even when older |
| Redirects | `followsARedirectOnlyToAnAllowlistedHost` | a redirect staying on an allowed host is followed |
| Redirects | `refusesARedirectOutsideTheAllowedHosts` | a redirect naming a foreign host is refused, jar untouched |
| Redirects | `refusesARedirectThatChangesTheScheme` | no hop may change the scheme, in either direction |
| Redirects | `givesUpAfterTooManyRedirects` | a redirect loop ends in an error, not a hang |
| Pre-releases | `installsAPreReleaseWhenAsked` | `--pre-releases` installs the newer pre-release |
| Feed hardening | `rejectsADraftRelease` | a draft release is refused |
| Feed hardening | `rejectsATagThatIsNotAVersionThisToolWouldPublish` | a feed tag that is not a version is refused |
| Feed hardening | `rejectsAReleaseWithoutTheJarAsset` | a release with no jar asset is refused |
| Feed hardening | `refusesADownloadUrlOutsideThisRepository` | an asset URL naming another host is refused before connecting |
| Feed hardening | `reportsWhenNothingExistsAtThePinnedTag` | a pinned tag that does not exist is reported |
| Feed hardening | `reportsAServerErrorInsteadOfGuessing` | an HTTP 500 is reported as an error |
| Repository home | `updatesComeFromTheRepositoryHome` | the update feed and download prefix point at the repository's real home, `neo4j-labs/neo4j-cert-tool` |

## `DerTest` — DER encoding

The hand-written DER encoder/reader everything else stands on.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Lengths | `shortFormForUpTo127Bytes` | the short form is used up to 127 bytes |
| Lengths | `longFormFrom128Bytes` | the long form from 128 bytes |
| Lengths | `lengthsRoundTripThroughTheReader` | lengths round-trip through the reader |
| Object identifiers | `encodesKnownOids` | known OIDs encode correctly |
| Object identifiers | `roundTripsThroughDecode` | OIDs round-trip through decode |
| Object identifiers | `rejectsAnInvalidFirstArc` | an invalid first arc is rejected |
| Object identifiers | `rejectsASingleArc` | a single-arc OID is rejected |
| Object identifiers | `rejectsATruncatedEncoding` | a truncated OID is rejected |
| Primitives | `booleanTrueIsAllOnes` | TRUE is encoded as all ones, as DER requires |
| Primitives | `integersUseMinimalTwosComplement` | integers use minimal two's-complement encoding |
| Primitives | `largeSerialNumbersSurviveEncoding` | 128-bit serial numbers survive encoding |
| Primitives | `bitStringRecordsUnusedBits` | bit strings record their unused trailing bits |
| Primitives | `bitStringRejectsAnImpossibleUnusedBitCount` | an impossible unused-bit count is rejected |
| Primitives | `nullIsEmpty` | NULL encodes as empty |
| Primitives | `printableStringRejectsCharactersOutsideItsRepertoire` | PrintableString rejects out-of-repertoire characters |
| Primitives | `utf8StringCarriesNonAsciiText` | UTF8String carries non-ASCII text |
| Primitives | `ia5StringRejectsNonAscii` | IA5String rejects non-ASCII |
| Primitives | `explicitTaggingUsesTheConstructedContextClass` | explicit tagging uses the constructed context class |
| Primitives | `contextPrimitiveTaggingIsUsedForGeneralNames` | context-primitive tagging is used for general names |
| Times | `usesUtcTimeBefore2050` | UTCTime before 2050 |
| Times | `usesGeneralizedTimeFrom2050` | GeneralizedTime from 2050 |
| Reader | `skipElementLandsOnTheNextElement` | skipping an element lands on the next |
| Reader | `skipElementHandlesLongFormLengths` | skipping handles long-form lengths |
| Reader | `rejectsAnUnexpectedTag` | an unexpected tag is rejected |
| Reader | `rejectsTruncatedInput` | truncated input is rejected |
| Reader | `rejectsAnElementThatOverrunsItsParent` | an element overrunning its parent is rejected |
| Public keys | `matchesTheJdkKeyIdentifierForAnEcKey` | the subject-public-key bits match the JDK's key identifier for EC |
| Public keys | `matchesTheJdkKeyIdentifierForAnRsaKey` | and for RSA |
| Public keys | `rejectsSomethingThatIsNotASubjectPublicKeyInfo` | non-SPKI input is rejected |

## `IpLiteralTest` — IP literal parsing

The deliberately strict IPv4/IPv6 parser used for SANs and name constraints.

| Feature | Test | What it verifies |
| --- | --- | --- |
| IPv4 | `parsesDottedQuads` | valid dotted quads parse to four octets |
| IPv4 | `rejectsMalformedDottedQuads` | malformed dotted quads are refused |
| IPv6 | `parsesAddresses` | valid IPv6 addresses parse to sixteen octets |
| IPv6 | `parsesEmbeddedIpv4` | an embedded dotted-quad tail parses |
| IPv4-mapped | `collapsesIpv4Mapped` | an IPv4-mapped address collapses to four octets, so a v4 peer can match it |
| IPv4-mapped | `rejectsMalformedAddresses` | malformed addresses are refused |
| Strictness | `refusesThreePartForm` | the legacy three-part form is refused rather than padded |
| Strictness | `refusesLeadingZeros` | leading zeros are refused — some readers take them as octal |
| Strictness | `refusesZoneIdentifier` | a zone identifier is refused rather than silently dropped |
| Strictness | `reportsIpv6NamesAsSuch` | a rejected IPv6-looking name gives an IPv6 error, not a hostname error |
| Hostnames | `areNeverMistakenForAddresses` | hostnames are never classified as addresses |
| Hostnames | `doNotResolve` | classification never performs a DNS lookup |
| Hostnames | `handlesAbsentInput` | null and empty are simply not addresses |

## `PemTest` — PEM encoding

| Feature | Test | What it verifies |
| --- | --- | --- |
| Encoding | `roundTripsArbitraryContent` | arbitrary binary content round-trips |
| Encoding | `wrapsTheBodyAtSixtyFourCharacters` | the body wraps at 64 characters, as RFC 7468 requires |
| Encoding | `endsWithANewlineSoBlocksConcatenateCleanly` | blocks end with a newline so chains concatenate cleanly |
| Decoding | `decodesTheFirstBlockWithAMatchingLabel` | the first block with the expected label decodes |
| Decoding | `toleratesCarriageReturnsAndSurroundingText` | CRLF and surrounding text are tolerated |
| Decoding | `reportsAMissingBlock` | a missing block is reported |
| Decoding | `reportsAnUnterminatedBlock` | an unterminated block is reported |
| Detection | `detectsWhichLabelsArePresent` | label detection answers which blocks a document holds |

## `Pkcs8Test` — private-key encryption

| Feature | Test | What it verifies |
| --- | --- | --- |
| Round trip | `encryptedKeysRoundTripForEveryKeyType` | encrypted keys round-trip for every key type |
| Decryption | `theWrongPasswordFails` | a wrong password fails cleanly |
| Decryption | `aTruncatedPasswordFails` | a truncated password fails |
| Decryption | `aCorruptedCiphertextFailsRatherThanYieldingAKey` | a flipped bit in the stored blob fails loudly instead of decoding to a usable key |
| Randomness | `theSameKeyEncryptsDifferentlyEachTime` | fresh salt and IV each time |
| Refusals | `emptyPasswordsAreRefused` | an empty password is refused |
| Refusals | `tooFewIterationsAreRefused` | an iteration count below the floor is refused |
| Refusals | `theProductionDefaultIsSixHundredThousandIterations` | the default iteration count is pinned at 600,000, the OWASP guidance for PBKDF2-HMAC-SHA256 |
| Scheme | `theEncryptionSchemeIsPbes2WithAes256AndHmacSha256` | PBES2 with AES-256 and HMAC-SHA256, as Neo4j reads |
| Scheme | `theIterationCountReachesTheEncodedParameters` | the iteration count reaches the encoded parameters |
| Scheme | `theSaltIsSixteenBytes` | the salt is sixteen bytes |
| Scheme | `theEncryptionSchemeIsAes256Cbc` | the cipher is AES-256-CBC |
| Scheme | `thePbkdf2PrfIsHmacSha256` | the PBKDF2 PRF is HMAC-SHA256 (the encoding bug the tool works around) |
| Plain keys | `theKeyAlgorithmCanBeReadBackFromAnUnencryptedKey` | the algorithm reads back from an unencrypted key |
| Plain keys | `anUnknownKeyAlgorithmIsReported` | an unknown key algorithm is reported |
| Plain keys | `unencryptedKeysCanStillBeRead` | unencrypted keys can still be read |

## `KeyTypeTest` — key-generation strength

That the raw key material has exactly the strength each `KeyType` claims — everything downstream
can be correct while the keys themselves are silently weaker.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Key strength | `generatedKeysHaveTheClaimedStrength` | EC keys sit on secp256r1/secp384r1 (not just any curve of the same size) and RSA moduli are 3072/4096 bits |
| Key pairing | `thePrivateKeyBelongsToItsPublicKey` | the private key signs and its own public key verifies, per key type |
| Randomness | `generatedKeyPairsAreDistinct` | two generated key pairs are never the same |
| Randomness | `generationConsumesTheSuppliedRandomness` | generation draws at least a seed's worth of entropy from the `SecureRandom` it was given |
| Parsing | `unknownNamesAreRejected` | unknown or empty key-type names are rejected |
| Parsing | `aliasesResolve` | `ec` and `rsa` resolve to the same types as their canonical names |

## `SignatureAlgorithmTest` — signature-algorithm selection

That the digest is never the weakest link in a certificate's signature.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Digest matching | `p256GetsSha256` | P-256 keys sign with SHA-256 |
| Digest matching | `p384GetsSha384` | P-384 keys sign with SHA-384 |
| Digest matching | `p521GetsSha512` | P-521 keys sign with SHA-512 (not a generated type, but the mapping must scale) |
| Digest matching | `rsaGetsSha256` | RSA keys sign with SHA-256 |
| Refusals | `unsupportedKeysAreRefused` | a DSA key is refused, not signed with some default |

## `AgentRegistryTest` — agent registry

| Feature | Test | What it verifies |
| --- | --- | --- |
| Lookup | `resolvesIdsCaseInsensitively` | agent ids resolve case-insensitively; unknown ids do not |
| Detection | `detectsAnAgentByItsConfigDirectory` | an agent counts as installed when its config directory exists |
| Paths | `derivesTheSkillsDirectoryFromTheHomeProperty` | skill directories derive from the user's home |

## `SkillTest` — agent skills

Self-skill, catalog and managed operations, against a local server impersonating the catalog.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Self-skill | `installsIntoADetectedAgentAndReportsItsVersion` | the bundle installs with frontmatter intact and records its version |
| Self-skill | `detectsDriftWhenTheInstalledContentIsEdited` | a hand-edited bundle is reported as drift |
| Self-skill | `detectsDriftWhenTheRunningVersionChanges` | a version bump makes the installed bundle stale |
| Self-skill | `isAddressableAsSelfOrByTheToolName` | `self` and the tool's own name both select the self-skill |
| Catalog | `fetchesAndCachesTheSkillNames` | the catalog fetches once and the fresh cache is not refetched |
| Catalog | `fallsBackToTheCacheWhenTheNetworkFails` | a forced fetch against a dead network falls back to the cache, with a warning |
| Catalog | `failsClearlyWithNoCacheAndNoNetwork` | no cache and no network is a clear error |
| Catalog | `refetchesWhenTheCacheGoesStale` | a cache past its TTL is fetched again |
| Catalog | `fallsBackToAStaleCacheWhenTheNetworkFails` | a stale cache plus a dead network still serves the cached names, with a warning |
| Catalog | `refetchesPastAnUnreadableTimestamp` | a corrupt freshness stamp does not pin the cache |
| Catalog | `rejectsAnUnknownSkillName` | an unknown catalog skill is reported with the remedy |
| Managed skills | `installsTheSelfSkillIntoEveryDetectedAgent` | a bare install reaches every detected agent |
| Managed skills | `installsACatalogSkillByCopy` | a catalog skill installs by copy, escapes and all |
| Managed skills | `reportsCheckAsCleanAfterAnInstall` | a fresh install checks clean |
| Managed skills | `reportsCheckAsDriftedAfterTheVersionChanges` | a version bump is reported as drift |
| Managed skills | `installsAMultiFileCatalogSkillWhole` | a catalog skill with reference files installs whole and checks clean |
| Managed skills | `removingAnAbsentSkillIsQuiet` | removing a skill that was never installed reports nothing |
| Managed skills | `refusesToOperateWhenNoAgentIsKnown` | no detected agent and no `--agent` is an error naming the remedy |
| Managed skills | `listsAreHonestAboutHavingNoAgents` | listing with no agents says so instead of printing nothing |
| Managed skills | `removesTheSelfSkillWhenNamedExplicitly` | `remove self` removes the self-skill |
| Managed skills | `checkSurvivesAnUnreachableCatalogAndStillReportsSelfDrift` | a catalog outage degrades to self-only, announced once |
| Managed skills | `removesEveryCatalogSkillButPreservesSelf` | `remove --all` clears catalog skills and preserves the self-skill |
| Managed skills | `autoRefreshUpdatesAStaleBundle` | auto-refresh brings a stale bundle up to the running version |

## `UpdateNoticeTest` — the once-a-day update notice

The automatic check that announces a newer release on interactive runs.

| Feature | Test | What it verifies |
| --- | --- | --- |
| Due-ness | `isFirstRunOfTheDay` | no stamp yet: the check is due |
| Due-ness | `isNotDueAgainWithinTheDay` | a stamp from moments ago holds the day |
| Due-ness | `comesDueAgainAfterTwentyFourHours` | yesterday's stamp is stale |
| Due-ness | `comesDueWhenTheStampIsUnreadable` | a corrupt stamp must not silence the check |
| Due-ness | `neverRunsForADevelopmentBuild` | a development build has nothing to compare against |
| Announcement | `announcesANewerReleaseWithTheRemedy` | the notice names the release, the running version and the update command |
| Announcement | `staysQuietWhenCurrent` | no announcement when up to date |
| Announcement | `checksOnlyOncePerDay` | the second look on the same day is not due |
| Announcement | `isSilentWhenTheNetworkIsDead` | a failed courtesy announces nothing |
| Announcement | `spendsTheDaysAttemptEvenWhenItFails` | the stamp is written before the attempt, bounding the cost to once a day |
| Opt-outs | `theEnvironmentVariableDisablesIt` | `NEO4J_CERT_TOOL_UPDATE_CHECK=false` disables, in any case |
| Opt-outs | `theCacheRootIsWhereTheStampLives` | the stamp shares the tool's cache root, so clearing the cache clears it |

---

## Conventions

- Tests that talk HTTP stand up a `com.sun.net.httpserver.HttpServer` on a loopback port; nothing
  leaves the machine. `UpdateTest` and `SkillTest` impersonate GitHub, and their fake servers
  accept per-test overrides for the guard-rail cases.
- Tests that assert POSIX permissions skip themselves where the file system has no mode bits; the
  CI matrix runs them for real on all three operating systems.
- `TestBundles` is a shared fixture builder, not a test class.
- The full build (`mvn verify`) also runs the smoke-generating step CI uses: a real bundle
  generated, installed and verified on the runner's own file system.
