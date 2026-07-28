package com.neo4j.tools.certtool.output;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Creates files and directories with the permissions Neo4j expects, on POSIX systems and on
 * Windows.
 *
 * <p>Permissions are applied when the file is created rather than afterwards, so a private key is
 * never briefly world readable between being written and being locked down.
 */
public final class FilePermissions {

    /** {@code 0400}: only the owner may read. Used for private keys and password files. */
    public static final Set<PosixFilePermission> OWNER_READ_ONLY =
            PosixFilePermissions.fromString("r--------");

    /** {@code 0600}: owner read and write. Used while a restricted file is being replaced. */
    public static final Set<PosixFilePermission> OWNER_READ_WRITE =
            PosixFilePermissions.fromString("rw-------");

    /** {@code 0644}: world readable. Certificates are public information. */
    public static final Set<PosixFilePermission> PUBLIC_READ =
            PosixFilePermissions.fromString("rw-r--r--");

    /** {@code 0755}: the permission Neo4j documents for the certificate directories. */
    public static final Set<PosixFilePermission> PUBLIC_DIRECTORY =
            PosixFilePermissions.fromString("rwxr-xr-x");

    /** {@code 0700}: staging directories, which hold private keys before they are distributed. */
    public static final Set<PosixFilePermission> PRIVATE_DIRECTORY =
            PosixFilePermissions.fromString("rwx------");

    private FilePermissions() {}

    /** Whether the file system supports POSIX permission bits. */
    public static boolean posixSupported() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    /** Creates a directory, and any missing parents, with the given permissions. */
    public static Path createDirectories(Path directory, Set<PosixFilePermission> permissions)
            throws IOException {
        if (Files.isDirectory(directory)) {
            applyToExisting(directory, permissions);
            return directory;
        }
        Path parent = directory.getParent();
        if (parent != null && !Files.isDirectory(parent)) {
            // Parents of a staging tree are created with the same restriction as the tree itself.
            createDirectories(parent, permissions);
        }
        Files.createDirectory(directory, attributes(permissions));
        if (!posixSupported()) {
            restrictAclIfPrivate(directory, permissions);
        }
        return directory;
    }

    /**
     * Writes a file, replacing any existing one, with the given permissions set at creation time.
     */
    public static void write(Path file, byte[] content, Set<PosixFilePermission> permissions)
            throws IOException {
        // Remove any existing file rather than truncating it: the old file may have looser
        // permissions, or be a symlink pointing somewhere else entirely.
        Files.deleteIfExists(file);
        try (var channel = Files.newByteChannel(
                file,
                EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                attributes(permissions))) {
            channel.write(java.nio.ByteBuffer.wrap(content));
        }
        if (!posixSupported()) {
            restrictAclIfPrivate(file, permissions);
        }
    }

    public static void write(Path file, String content, Set<PosixFilePermission> permissions)
            throws IOException {
        write(file, content.getBytes(StandardCharsets.UTF_8), permissions);
    }

    /** Reports the current POSIX permissions, or empty on a file system without them. */
    public static Set<PosixFilePermission> read(Path path) throws IOException {
        if (!posixSupported()) {
            return Set.of();
        }
        return Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
    }

    /** Formats a permission set as a symbolic mode, for messages: {@code r-------- (0400)}. */
    public static String describe(Set<PosixFilePermission> permissions) {
        if (permissions.isEmpty()) {
            return "owner-only ACL";
        }
        String symbolic = PosixFilePermissions.toString(permissions);
        int octal = 0;
        for (PosixFilePermission permission : permissions) {
            octal |= switch (permission) {
                case OWNER_READ -> 0400;
                case OWNER_WRITE -> 0200;
                case OWNER_EXECUTE -> 0100;
                case GROUP_READ -> 0040;
                case GROUP_WRITE -> 0020;
                case GROUP_EXECUTE -> 0010;
                case OTHERS_READ -> 0004;
                case OTHERS_WRITE -> 0002;
                case OTHERS_EXECUTE -> 0001;
            };
        }
        return "%s (%04o)".formatted(symbolic, octal);
    }

    /** Whether anyone other than the owner can read this path. */
    public static boolean readableByOthers(Path path) throws IOException {
        Set<PosixFilePermission> permissions = read(path);
        return permissions.contains(PosixFilePermission.GROUP_READ)
                || permissions.contains(PosixFilePermission.OTHERS_READ);
    }

    private static FileAttribute<?>[] attributes(Set<PosixFilePermission> permissions) {
        // On Windows there is no POSIX view, so the attribute is omitted and an ACL is applied
        // after creation instead.
        return posixSupported()
                ? new FileAttribute<?>[] {PosixFilePermissions.asFileAttribute(permissions)}
                : new FileAttribute<?>[0];
    }

    private static void applyToExisting(Path path, Set<PosixFilePermission> permissions)
            throws IOException {
        if (posixSupported()) {
            Files.setPosixFilePermissions(path, permissions);
        } else {
            restrictAclIfPrivate(path, permissions);
        }
    }

    /**
     * On Windows, replaces the ACL with a single owner entry when the POSIX equivalent would have
     * denied access to group and others.
     *
     * <p>Setting an explicit ACL also stops inherited entries from applying, which is what makes
     * this equivalent to {@code chmod 0400} on a directory that grants Users read access.
     */
    private static void restrictAclIfPrivate(Path path, Set<PosixFilePermission> permissions)
            throws IOException {
        boolean ownerOnly = permissions.stream()
                .noneMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"));
        if (!ownerOnly) {
            return;
        }
        AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
        if (view == null) {
            // Neither POSIX nor ACL support: nothing can be enforced, so say so rather than
            // pretending the file is protected.
            throw new IOException(
                    "This file system supports neither POSIX permissions nor ACLs, so "
                            + path
                            + " cannot be restricted to its owner");
        }
        UserPrincipal owner = view.getOwner();
        Set<AclEntryPermission> everything = EnumSet.allOf(AclEntryPermission.class);
        AclEntry ownerEntry = AclEntry.newBuilder()
                .setType(AclEntryType.ALLOW)
                .setPrincipal(owner)
                .setPermissions(everything)
                .build();
        view.setAcl(List.of(ownerEntry));
    }
}
