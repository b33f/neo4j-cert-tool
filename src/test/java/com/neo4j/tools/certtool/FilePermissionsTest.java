package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.neo4j.tools.certtool.model.Scope;
import com.neo4j.tools.certtool.output.FilePermissions;
import com.neo4j.tools.certtool.output.Layout;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Checks the permissions of the generated files against the table in Neo4j's SSL framework
 * documentation.
 *
 * <p>Skipped on file systems without POSIX permissions, where {@code FilePermissions} falls back to
 * owner-only ACLs instead.
 */
class FilePermissionsTest {

    @BeforeEach
    void requirePosix() {
        assumeTrue(FilePermissions.posixSupported(), "requires a POSIX file system");
    }

    @ParameterizedTest
    @EnumSource(Scope.class)
    @DisplayName("private.key is 0400, public.crt is 0644, directories are 0755")
    void permissionsMatchTheDocumentedTable(Scope scope, @TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");
        Path node = run.node("core1");

        assertMode("r--------", Layout.privateKey(node, scope));
        assertMode("rw-r--r--", Layout.publicCertificate(node, scope));
        assertMode("rwxr-xr-x", Layout.scope(node, scope));
        assertMode("rwxr-xr-x", Layout.trusted(node, scope));
        assertMode("rwxr-xr-x", Layout.revoked(node, scope));
        assertMode("rwxr-xr-x", Layout.certificates(node));
    }

    @Test
    @DisplayName("the staging directory is 0700, because it holds every node's keys")
    void theStagingDirectoryIsPrivate(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        assertMode("rwx------", run.outputDirectory());
        assertMode("rwx------", run.node("core1"));
        assertMode("rwx------", run.caDirectory());
    }

    @Test
    @DisplayName("the CA private key is 0400")
    void theCaKeyIsProtected(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        assertMode("r--------", run.caDirectory().resolve(Layout.CA_KEY_FILE));
        assertMode("rw-r--r--", run.caDirectory().resolve(Layout.CA_CERTIFICATE_FILE));
    }

    @Test
    @DisplayName("the conf snippet is 0400, because it contains the key password")
    void theConfSnippetIsProtected(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");
        Path snippet = run.node("core1").resolve(Layout.CONF_SNIPPET_FILE);

        assertMode("r--------", snippet);
        assertTrue(
                Files.readString(snippet).contains("private_key_password=" + TestBundles.PASSWORD),
                "Neo4j needs the password in clear text, so the file holding it must be locked down");
    }

    @Test
    @DisplayName("no generated file is readable by group or others except certificates")
    void onlyPublicMaterialIsWorldReadable(@TempDir Path directory) throws Exception {
        TestBundles.Run run = TestBundles.twoNodeCluster(directory, "ca");

        try (var walk = Files.walk(run.outputDirectory())) {
            for (Path path : walk.filter(Files::isRegularFile).toList()) {
                boolean shared = FilePermissions.readableByOthers(path);
                String name = path.getFileName().toString();
                boolean isPublic = name.endsWith(".crt");
                assertEquals(
                        isPublic,
                        shared,
                        path + " should " + (isPublic ? "" : "not ") + "be readable by others");
            }
        }
    }

    @Test
    @DisplayName("a private key is never briefly world readable while being written")
    void keysAreCreatedWithTheirFinalPermissions(@TempDir Path directory) throws Exception {
        // Written through an open channel on a file created with mode 0400, so there is no window
        // in which the key exists with looser permissions.
        Path file = directory.resolve("key.pem");
        FilePermissions.write(file, "secret", FilePermissions.OWNER_READ_ONLY);

        assertMode("r--------", file);
        assertEquals("secret", Files.readString(file));
    }

    @Test
    @DisplayName("writing over an existing loose file replaces its permissions")
    void existingFilesAreReplacedNotTruncated(@TempDir Path directory) throws Exception {
        Path file = directory.resolve("key.pem");
        Files.writeString(file, "old");
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-rw-rw-"));

        FilePermissions.write(file, "new", FilePermissions.OWNER_READ_ONLY);

        assertMode("r--------", file);
        assertEquals("new", Files.readString(file));
    }

    @Test
    @DisplayName("a symlink in the way is replaced, not followed")
    void symlinksAreNotFollowed(@TempDir Path directory) throws Exception {
        // A key written through a symlink would land wherever the link points, with whatever
        // permissions that location has.
        Path target = directory.resolve("elsewhere.txt");
        Files.writeString(target, "untouched");
        Path link = directory.resolve("private.key");
        Files.createSymbolicLink(link, target);

        FilePermissions.write(link, "secret", FilePermissions.OWNER_READ_ONLY);

        assertFalse(Files.isSymbolicLink(link));
        assertEquals("untouched", Files.readString(target));
        assertEquals("secret", Files.readString(link));
        assertMode("r--------", link);
    }

    @Test
    @DisplayName("the permission describer renders both symbolic and octal forms")
    void permissionsAreDescribedReadably() {
        assertEquals("r-------- (0400)", FilePermissions.describe(FilePermissions.OWNER_READ_ONLY));
        assertEquals("rw-r--r-- (0644)", FilePermissions.describe(FilePermissions.PUBLIC_READ));
        assertEquals("rwxr-xr-x (0755)", FilePermissions.describe(FilePermissions.PUBLIC_DIRECTORY));
        assertEquals("rwx------ (0700)", FilePermissions.describe(FilePermissions.PRIVATE_DIRECTORY));
    }

    private static void assertMode(String expected, Path path) throws Exception {
        Set<PosixFilePermission> actual = FilePermissions.read(path);
        assertEquals(expected, PosixFilePermissions.toString(actual), path.toString());
    }
}
