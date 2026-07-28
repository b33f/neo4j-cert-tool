package com.neo4j.tools.certtool;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Covers password sourcing, including the hand-written password file parser.
 *
 * <p>The parser decodes bytes into {@code char[]} itself rather than going through
 * {@link Files#readAllLines}, so that a password never exists as an immutable String. That means the
 * line handling is this project's code and needs its own tests.
 */
class PasswordProviderTest {

    private final SecureRandom random = new SecureRandom();

    private Path write(Path directory, String name, String content) throws IOException {
        Path file = directory.resolve(name);
        Files.write(file, content.getBytes(StandardCharsets.UTF_8));
        return file;
    }

    @Nested
    @DisplayName("password file parsing")
    class Parsing {

        @Test
        void aSingleBareLineAppliesToEverySubject(@TempDir Path directory) throws Exception {
            Path file = write(directory, "pw.txt", "one-password-for-all\n");
            try (PasswordProvider passwords = PasswordProvider.fromFile(file, random)) {
                assertArrayEquals("one-password-for-all".toCharArray(), passwords.forSubject("core1"));
                assertArrayEquals("one-password-for-all".toCharArray(), passwords.forSubject("ca"));
            }
        }

        @Test
        void windowsLineEndingsAreHandled(@TempDir Path directory) throws Exception {
            // A password file edited on Windows would otherwise pick up a trailing \r, which would
            // silently become part of the password and make every key undecryptable.
            Path file = write(directory, "pw.txt", "core1=first-password\r\ncore2=second-password\r\n");
            try (PasswordProvider passwords = PasswordProvider.fromFile(file, random)) {
                assertArrayEquals("first-password".toCharArray(), passwords.forSubject("core1"));
                assertArrayEquals("second-password".toCharArray(), passwords.forSubject("core2"));
            }
        }

        @Test
        void aMissingFinalNewlineIsFine(@TempDir Path directory) throws Exception {
            Path file = write(directory, "pw.txt", "no-trailing-newline");
            try (PasswordProvider passwords = PasswordProvider.fromFile(file, random)) {
                assertArrayEquals("no-trailing-newline".toCharArray(), passwords.forSubject("any"));
            }
        }

        @Test
        void commentsAndBlankLinesAreIgnored(@TempDir Path directory) throws Exception {
            Path file = write(
                    directory,
                    "pw.txt",
                    """
                    # cluster passwords

                      # indented comment
                    core1=the-first-password

                    core2=the-second-password
                    """);
            try (PasswordProvider passwords = PasswordProvider.fromFile(file, random)) {
                assertArrayEquals("the-first-password".toCharArray(), passwords.forSubject("core1"));
                assertArrayEquals("the-second-password".toCharArray(), passwords.forSubject("core2"));
            }
        }

        @Test
        void whitespaceAroundTheSubjectIsTrimmedButNotInsideThePassword(@TempDir Path directory)
                throws Exception {
            // Trailing spaces in a password are preserved deliberately; a password is taken as
            // written apart from the line ending.
            Path file = write(directory, "pw.txt", "  core1  =  a password with spaces  \n");
            try (PasswordProvider passwords = PasswordProvider.fromFile(file, random)) {
                assertArrayEquals(
                        "  a password with spaces".toCharArray(), passwords.forSubject("core1"));
            }
        }

        @Test
        void mixingBothFormsIsRejected(@TempDir Path directory) throws Exception {
            Path file = write(directory, "pw.txt", "a-bare-password\ncore1=another-password\n");
            IOException failure =
                    assertThrows(IOException.class, () -> PasswordProvider.fromFile(file, random));
            assertTrue(failure.getMessage().contains("but not both"), failure.getMessage());
        }

        @Test
        void twoBareLinesAreRejected(@TempDir Path directory) throws Exception {
            Path file = write(directory, "pw.txt", "first\nsecond\n");
            assertThrows(IOException.class, () -> PasswordProvider.fromFile(file, random));
        }

        @Test
        void anEmptyFileIsRejected(@TempDir Path directory) throws Exception {
            Path file = write(directory, "pw.txt", "# only a comment\n\n");
            IOException failure =
                    assertThrows(IOException.class, () -> PasswordProvider.fromFile(file, random));
            assertTrue(failure.getMessage().contains("no password found"), failure.getMessage());
        }

        @Test
        void anUnknownSubjectWithNoDefaultIsReported(@TempDir Path directory) throws Exception {
            Path file = write(directory, "pw.txt", "core1=the-first-password\n");
            try (PasswordProvider passwords = PasswordProvider.fromFile(file, random)) {
                assertThrows(IllegalStateException.class, () -> passwords.forSubject("core9"));
            }
        }

        @Test
        void nonAsciiPasswordsSurviveTheRoundTrip(@TempDir Path directory) throws Exception {
            // The parser decodes UTF-8 itself, so a multi-byte character must not be mangled.
            String password = "pässwörd-with-ümlauts-日本語";
            Path file = write(directory, "pw.txt", "core1=" + password + "\n");
            try (PasswordProvider passwords = PasswordProvider.fromFile(file, random)) {
                assertArrayEquals(password.toCharArray(), passwords.forSubject("core1"));
            }
        }

        @Test
        void readSingleFromTakesTheFirstRealLine(@TempDir Path directory) throws Exception {
            Path file = write(directory, "ca.txt", "# the CA password\n\n  the-ca-password  \n");
            char[] password = PasswordProvider.readSingleFrom(file);
            assertArrayEquals("the-ca-password".toCharArray(), password);
        }

        @Test
        void readSingleFromRejectsAFileWithNothingInIt(@TempDir Path directory) throws Exception {
            Path file = write(directory, "ca.txt", "\n# nothing here\n");
            assertThrows(IOException.class, () -> PasswordProvider.readSingleFrom(file));
        }
    }

    @Nested
    @DisplayName("generated passwords")
    class Generated {

        @Test
        void areLongAndUseOnlyConfigSafeCharacters() {
            try (PasswordProvider passwords = PasswordProvider.generating(random)) {
                char[] password = passwords.forSubject("core1");

                // 24 bytes of entropy, base64url without padding, so 32 characters.
                assertEquals(32, password.length);
                for (char c : password) {
                    boolean safe = (c >= 'A' && c <= 'Z')
                            || (c >= 'a' && c <= 'z')
                            || (c >= '0' && c <= '9')
                            || c == '-'
                            || c == '_';
                    assertTrue(safe, "character '" + c + "' is not safe to paste into neo4j.conf");
                }
            }
        }

        @Test
        void differPerSubjectAndAreStableWithinOne() {
            try (PasswordProvider passwords = PasswordProvider.generating(random)) {
                char[] first = passwords.forSubject("core1");
                char[] second = passwords.forSubject("core2");

                assertNotEquals(new String(first), new String(second), "nodes must not share a password");
                // All of a node's scope keys share that node's password, so repeated lookups match.
                assertArrayEquals(first, passwords.forSubject("core1"));
            }
        }

        @Test
        void areReportedForTheRunSummary() {
            try (PasswordProvider passwords = PasswordProvider.generating(random)) {
                passwords.forSubject("ca");
                passwords.forSubject("core1");
                assertEquals(2, passwords.generatedPasswords().size());
            }
        }

        @Test
        void suppliedPasswordsAreNotEchoedBack(@TempDir Path directory) throws Exception {
            // A password the user chose is theirs; repeating it in the summary would only put it
            // somewhere new.
            Path file = write(directory, "pw.txt", "a-supplied-password\n");
            try (PasswordProvider passwords = PasswordProvider.fromFile(file, random)) {
                passwords.forSubject("core1");
                assertTrue(passwords.generatedPasswords().isEmpty());
            }
        }
    }

    @Test
    @DisplayName("closing zeroes every password it was holding")
    void closingZeroesPasswords(@TempDir Path directory) throws Exception {
        Path file = write(directory, "pw.txt", "core1=a-password-to-clear\n");
        PasswordProvider passwords = PasswordProvider.fromFile(file, random);
        char[] held = passwords.forSubject("core1");
        assertArrayEquals("a-password-to-clear".toCharArray(), held);

        passwords.close();

        assertArrayEquals(new char[held.length], held, "the password array must be zeroed on close");
    }

    @Test
    @DisplayName("a generated password is zeroed on close too")
    void closingZeroesGeneratedPasswords() {
        PasswordProvider passwords = PasswordProvider.generating(random);
        char[] held = passwords.forSubject("core1");

        passwords.close();

        assertArrayEquals(new char[held.length], held);
    }
}
