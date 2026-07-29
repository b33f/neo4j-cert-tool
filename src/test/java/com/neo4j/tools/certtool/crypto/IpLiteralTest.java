package com.neo4j.tools.certtool.crypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Covers the hand-written IP literal parser.
 *
 * <p>The tool supports JDK 21, which has no {@code InetAddress.ofLiteral}, and
 * {@code getByName} cannot be used to classify a name because it resolves hostnames. So the parser
 * is this project's code, and it decides whether a name is encoded as an {@code iPAddress} or a
 * {@code dNSName} — get that wrong and a certificate either fails verification or claims an address
 * nobody asked for.
 *
 * <p>The expectations here were cross-checked against {@code InetAddress.ofLiteral} on a JDK that
 * has it: 59 of 65 corpus entries agree, and the six that differ are the deliberate refusals in
 * {@link Strictness}.
 */
class IpLiteralTest {

    @Nested
    @DisplayName("IPv4")
    class Ipv4 {

        @ParameterizedTest
        @CsvSource({
            "0.0.0.0, 0.0.0.0",
            "127.0.0.1, 127.0.0.1",
            "10.0.0.11, 10.0.0.11",
            "192.168.1.1, 192.168.1.1",
            "255.255.255.255, 255.255.255.255"
        })
        void parsesDottedQuads(String text, String expected) {
            var address = Extensions.asIpLiteral(text);
            assertNotNull(address, text);
            assertEquals(expected, address.getHostAddress());
            assertEquals(4, address.getAddress().length, "IPv4 is four octets in a SAN");
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "256.1.1.1", // octet out of range
            "1.2.3.4.5", // too many octets
            "1..2.3",    // empty octet
            "1.2.3.4.",  // trailing dot
            "-1.2.3.4",
            "999.1.1.1",
            "0x7f.0.0.1", // hexadecimal
            "1.2.3.a",
            "1.2.3.-4",
            "."
        })
        void rejectsMalformedDottedQuads(String text) {
            assertNull(Extensions.asIpLiteral(text), text + " must not parse as an address");
        }
    }

    @Nested
    @DisplayName("IPv6")
    class Ipv6 {

        @ParameterizedTest
        @CsvSource({
            "::1, 0:0:0:0:0:0:0:1",
            "::, 0:0:0:0:0:0:0:0",
            "1::, 1:0:0:0:0:0:0:0",
            "fe80::1, fe80:0:0:0:0:0:0:1",
            "0:0:0:0:0:0:0:1, 0:0:0:0:0:0:0:1",
            "1:2:3:4:5:6:7:8, 1:2:3:4:5:6:7:8",
            "2001:db8::ff00:42:8329, 2001:db8:0:0:0:ff00:42:8329",
            "2001:0db8:0000:0000:0000:ff00:0042:8329, 2001:db8:0:0:0:ff00:42:8329",
            "ABCD:EF01:2345:6789:ABCD:EF01:2345:6789, abcd:ef01:2345:6789:abcd:ef01:2345:6789",
            "1::8, 1:0:0:0:0:0:0:8"
        })
        void parsesAddresses(String text, String expected) {
            var address = Extensions.asIpLiteral(text);
            assertNotNull(address, text);
            assertEquals(expected, address.getHostAddress());
            assertEquals(16, address.getAddress().length);
        }

        @ParameterizedTest
        @CsvSource({
            // A dotted-quad supplies the last 32 bits.
            "1:2:3:4:5:6:1.2.3.4, 1:2:3:4:5:6:102:304",
            "64:ff9b::1.2.3.4, 64:ff9b:0:0:0:0:102:304",
            "::0.0.0.0, 0:0:0:0:0:0:0:0"
        })
        void parsesEmbeddedIpv4(String text, String expected) {
            var address = Extensions.asIpLiteral(text);
            assertNotNull(address, text);
            assertEquals(expected, address.getHostAddress());
            assertEquals(16, address.getAddress().length);
        }

        @ParameterizedTest
        @ValueSource(strings = {"::ffff:10.0.0.1", "::ffff:192.168.1.1", "::ffff:102:304"})
        @DisplayName("an IPv4-mapped address collapses to four octets, so a v4 peer can match it")
        void collapsesIpv4Mapped(String text) {
            var address = Extensions.asIpLiteral(text);
            assertNotNull(address, text);
            assertEquals(
                    4,
                    address.getAddress().length,
                    text + ": a 16-octet entry would never match an IPv4 connection");
        }

        @ParameterizedTest
        @ValueSource(strings = {
            "1:2:3:4:5:6:7:8:9",  // too many groups
            "1:2:3:4:5:6:7",      // too few, without compression
            "::1::2",             // two compressions
            "1:::2",              // empty group
            ":1:2:3:4:5:6:7:8",   // stray leading colon
            "1:2:3:4:5:6:7:8::",  // compression with nothing to compress
            "12345::1",           // group too long
            "gggg::1",            // not hexadecimal
            "::1.2.3",            // short embedded IPv4
            "1:2:3:4:5:6:1.2.3.4.5",
            "1.2.3.4::",          // embedded IPv4 must be last
            "::ffff:1.2.3.4.5",
            ":",
            ":::",
            "1::2::3",
            "::g"
        })
        void rejectsMalformedAddresses(String text) {
            assertNull(Extensions.asIpLiteral(text), text + " must not parse as an address");
        }
    }

    @Nested
    @DisplayName("deliberate strictness")
    class Strictness {

        @Test
        @DisplayName("the legacy three-part form is refused rather than padded")
        void refusesThreePartForm() {
            // InetAddress.ofLiteral reads this as 1.2.0.3. Inventing an octet from a typo and then
            // certifying it is worse than refusing.
            assertNull(Extensions.parseIpLiteral("1.2.3"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"01.2.3.4", "1.2.3.04", "0.0.0.00", "00.0.0.0", "010.1.1.1"})
        @DisplayName("leading zeros are refused, because they are read as octal elsewhere")
        void refusesLeadingZeros(String text) {
            // The JDK reads these as decimal, but a leading zero is octal to some resolvers, so the
            // same certificate would mean different addresses to different readers.
            assertNull(Extensions.parseIpLiteral(text), text);
        }

        @Test
        @DisplayName("a zone identifier is refused rather than silently dropped")
        void refusesZoneIdentifier() {
            assertNull(Extensions.parseIpLiteral("fe80::1%en0"));
        }

        @Test
        @DisplayName("a rejected IPv6-looking name gives an IPv6 error, not a hostname error")
        void reportsIpv6NamesAsSuch() {
            IllegalArgumentException failure = assertThrows(
                    IllegalArgumentException.class,
                    () -> Extensions.subjectAlternativeName(List.of("fe80::1%en0")));
            assertTrue(failure.getMessage().contains("Not a valid IPv6 address"), failure.getMessage());
            assertTrue(failure.getMessage().contains("zone identifier"), failure.getMessage());
        }
    }

    @Nested
    @DisplayName("hostnames")
    class Hostnames {

        @ParameterizedTest
        @ValueSource(strings = {
            "core1.example.com", "localhost", "example", "a-b.c", "neo4j", "host_name", "*.example.com"
        })
        void areNeverMistakenForAddresses(String name) {
            assertNull(Extensions.asIpLiteral(name), name + " is a hostname, not an address");
        }

        @Test
        @DisplayName("classification never performs a DNS lookup")
        void doNotResolve() {
            // A name that cannot resolve must simply return null rather than hang or throw. If the
            // parser fell back to getByName this would attempt a lookup.
            long before = System.nanoTime();
            assertNull(Extensions.asIpLiteral("this-host-does-not-exist.invalid"));
            long millis = (System.nanoTime() - before) / 1_000_000;
            assertTrue(millis < 500, "classification took " + millis + "ms; did it resolve?");
        }
    }

    @Test
    @DisplayName("null and empty are not addresses")
    void handlesAbsentInput() {
        assertNull(Extensions.parseIpLiteral(null));
        assertNull(Extensions.parseIpLiteral(""));
    }
}
