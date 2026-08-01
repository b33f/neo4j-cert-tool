package com.neo4j.tools.certtool.model;

import com.neo4j.tools.certtool.crypto.Extensions;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The limits placed on what a generated certificate authority may issue for.
 *
 * <p>A CA that can sign anything is a liability: whoever holds its key can mint a certificate for
 * {@code google.com}, and every machine trusting that CA will believe it. RFC 5280 name constraints
 * bind the CA to a set of names, so a stolen or misused key can only affect the deployment it was
 * created for.
 *
 * <p>The constraints are derived from the node names given, widened just enough that the CA remains
 * useful for adding members later:
 *
 * <ul>
 *   <li>DNS names are constrained to their <em>parent domain</em>, so a CA created for
 *       {@code core1.example.com} can later issue {@code core9.example.com} but never
 *       {@code google.com}.
 *   <li>IP addresses are constrained to the private or loopback range they fall in, so another node
 *       on the same network can be added, but a public address cannot be certified.
 * </ul>
 *
 * @param permittedDns permitted DNS subtrees; a subtree covers itself and anything beneath it
 * @param permittedIps permitted IP ranges
 * @param excludeAllIpAddresses exclude every IP address, used when the deployment has none
 */
public record NameConstraints(
        List<String> permittedDns, List<Cidr> permittedIps, boolean excludeAllIpAddresses) {

    /** An address range: a base address and the number of leading bits that are significant. */
    public record Cidr(InetAddress base, int prefixBits) {

        /**
         * Encodes as RFC 5280 requires for a name constraint: the address followed by its mask, so
         * eight octets for IPv4 and thirty-two for IPv6. Note this differs from a subjectAltName
         * entry, which carries the address alone.
         */
        public byte[] encoded() {
            byte[] address = base.getAddress();
            byte[] encoded = new byte[address.length * 2];
            System.arraycopy(address, 0, encoded, 0, address.length);
            for (int i = 0; i < address.length; i++) {
                int remaining = prefixBits - i * 8;
                int mask = remaining >= 8 ? 0xFF : remaining <= 0 ? 0x00 : (0xFF << (8 - remaining)) & 0xFF;
                encoded[address.length + i] = (byte) mask;
                // The base must not have bits set outside the prefix, or validators disagree.
                encoded[i] = (byte) (address[i] & mask);
            }
            return encoded;
        }

        /** Whether an address falls inside this range. */
        public boolean contains(InetAddress candidate) {
            byte[] mine = base.getAddress();
            byte[] theirs = candidate.getAddress();
            if (mine.length != theirs.length) {
                return false;
            }
            for (int i = 0; i < mine.length; i++) {
                int remaining = prefixBits - i * 8;
                int mask = remaining >= 8 ? 0xFF : remaining <= 0 ? 0x00 : (0xFF << (8 - remaining)) & 0xFF;
                if ((mine[i] & mask) != (theirs[i] & mask)) {
                    return false;
                }
            }
            return true;
        }

        @Override
        public String toString() {
            return base.getHostAddress() + "/" + prefixBits;
        }

        /** Parses {@code address/prefix}, or a bare address as a single host. */
        public static Cidr parse(String text) {
            int slash = text.indexOf('/');
            String addressPart = slash < 0 ? text : text.substring(0, slash);
            InetAddress address = Extensions.asIpLiteral(addressPart);
            if (address == null) {
                throw new IllegalArgumentException("Not an IP address: '" + addressPart + "'");
            }
            int bits = address.getAddress().length * 8;
            if (slash < 0) {
                return new Cidr(address, bits);
            }
            int prefix;
            try {
                prefix = Integer.parseInt(text.substring(slash + 1).trim());
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Not a prefix length: '" + text + "'");
            }
            if (prefix < 0 || prefix > bits) {
                throw new IllegalArgumentException(
                        "Prefix length must be 0 to " + bits + " for this address: '" + text + "'");
            }
            return new Cidr(address, prefix);
        }
    }

    /**
     * The ranges a derived IP constraint is widened to. An address inside one of these is
     * constrained to the whole range, so a sibling node can be added later without reissuing the CA.
     * Anything outside them — a public address — is constrained to itself.
     */
    private static final List<String> PRIVATE_RANGES = List.of(
            "10.0.0.0/8", // RFC 1918
            "172.16.0.0/12", // RFC 1918
            "192.168.0.0/16", // RFC 1918
            "100.64.0.0/10", // RFC 6598 carrier-grade NAT
            "127.0.0.0/8", // loopback
            "169.254.0.0/16", // link-local
            "fc00::/7", // RFC 4193 unique local
            "fe80::/10", // link-local
            "::1/128"); // loopback

    /** Constraints that permit nothing in particular, used when the feature is switched off. */
    public static NameConstraints none() {
        return new NameConstraints(List.of(), List.of(), false);
    }

    public boolean isEmpty() {
        return permittedDns.isEmpty() && permittedIps.isEmpty() && !excludeAllIpAddresses;
    }

    /**
     * Derives constraints from the names a cluster uses.
     *
     * @param extraDns additional DNS subtrees to permit, from {@code --permit-dns}
     * @param extraIps additional address ranges to permit, from {@code --permit-ip}
     */
    public static NameConstraints deriveFrom(
            Collection<NodeSpec> nodes, List<String> extraDns, List<String> extraIps) {
        Set<String> dns = new LinkedHashSet<>();
        List<Cidr> ips = new ArrayList<>();

        for (NodeSpec node : nodes) {
            for (String name : node.subjectAlternativeNames()) {
                InetAddress address = Extensions.asIpLiteral(name);
                if (address != null) {
                    addRange(ips, enclosingRange(address));
                } else {
                    dns.add(parentDomain(name));
                }
            }
        }
        for (String suffix : extraDns) {
            dns.add(suffix.trim().toLowerCase(Locale.ROOT));
        }
        for (String range : extraIps) {
            addRange(ips, Cidr.parse(range.trim()));
        }

        List<String> permittedDns = collapseDns(dns);
        // With no addresses anywhere, exclude the whole address space rather than leaving it
        // unconstrained: RFC 5280 only constrains name types that appear in the constraints, so
        // omitting IP entirely would leave the CA free to certify any address it liked.
        boolean excludeIps = ips.isEmpty();
        return new NameConstraints(permittedDns, List.copyOf(ips), excludeIps);
    }

    /**
     * The subtree a DNS name is constrained to: its parent domain, so siblings can be added later.
     *
     * <p>A two-label name keeps its full form. Stripping {@code example.com} to {@code com} would
     * permit every certificate in the top-level domain, which is barely a constraint at all.
     */
    public static String parentDomain(String name) {
        String lower = name.toLowerCase(Locale.ROOT);
        // A wildcard already covers its siblings; constrain to what it sits under.
        if (lower.startsWith("*.")) {
            lower = lower.substring(2);
        }
        int labels = lower.split("\\.", -1).length;
        if (labels <= 2) {
            return lower;
        }
        return lower.substring(lower.indexOf('.') + 1);
    }

    /** Removes any subtree already covered by a broader one, so the extension stays minimal. */
    private static List<String> collapseDns(Set<String> names) {
        List<String> kept = new ArrayList<>();
        for (String candidate : names) {
            boolean covered = names.stream()
                    .anyMatch(other -> !other.equals(candidate) && isUnder(candidate, other));
            if (!covered) {
                kept.add(candidate);
            }
        }
        return List.copyOf(kept);
    }

    /** Whether {@code name} sits at or beneath the subtree {@code base}. */
    public static boolean isUnder(String name, String base) {
        String lower = name.toLowerCase(Locale.ROOT);
        String suffix = base.toLowerCase(Locale.ROOT);
        if (lower.startsWith("*.")) {
            lower = lower.substring(2);
        }
        return lower.equals(suffix) || lower.endsWith("." + suffix);
    }

    private static Cidr enclosingRange(InetAddress address) {
        for (String range : PRIVATE_RANGES) {
            Cidr candidate = Cidr.parse(range);
            if (candidate.contains(address)) {
                return candidate;
            }
        }
        // A routable address gets no room to grow: it is constrained to exactly itself.
        return new Cidr(address, address.getAddress().length * 8);
    }

    private static void addRange(List<Cidr> ranges, Cidr candidate) {
        if (ranges.stream().anyMatch(existing -> covers(existing, candidate))) {
            return;
        }
        ranges.removeIf(existing -> covers(candidate, existing));
        ranges.add(candidate);
    }

    private static boolean covers(Cidr outer, Cidr inner) {
        return outer.base().getAddress().length == inner.base().getAddress().length
                && outer.prefixBits() <= inner.prefixBits()
                && outer.contains(inner.base());
    }

    /** Whether a name a node wants would be permitted by these constraints. */
    public boolean permits(String name) {
        InetAddress address = Extensions.asIpLiteral(name);
        if (address != null) {
            if (excludeAllIpAddresses) {
                return false;
            }
            return permittedIps.isEmpty() || permittedIps.stream().anyMatch(cidr -> cidr.contains(address));
        }
        return permittedDns.isEmpty() || permittedDns.stream().anyMatch(base -> isUnder(name, base));
    }

    /** One line per constraint, for the run summary, the dry run and the CA's own README. */
    public List<String> describe() {
        List<String> lines = new ArrayList<>();
        for (String suffix : permittedDns) {
            lines.add("DNS names at or below " + suffix);
        }
        for (Cidr cidr : permittedIps) {
            lines.add("IP addresses in " + cidr);
        }
        if (excludeAllIpAddresses) {
            lines.add("no IP addresses at all");
        }
        return lines;
    }
}
