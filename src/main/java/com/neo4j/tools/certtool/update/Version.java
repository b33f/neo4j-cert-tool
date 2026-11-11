package com.neo4j.tools.certtool.update;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * A release version, parsed from a tag such as {@code v1.2.1} or {@code v1.3.0-rc1}.
 *
 * <p>Orders by the numeric components first. At equal numbers, the plain release sorts after any
 * suffixed form ({@code 1.3.0} is newer than {@code 1.3.0-rc1}), as semver requires. Two suffixed
 * forms at the same x.y.z are compared textually with digits compared numerically, which covers the
 * {@code rc1}, {@code rc2}, ... sequence without dragging in a full semver implementation.
 *
 * @param major first component
 * @param minor second component
 * @param patch third component
 * @param suffix the prerelease part after the dash, or null for a stable release
 */
public record Version(int major, int minor, int patch, String suffix)
        implements Comparable<Version> {

    /**
     * Accepts the tags this project publishes, with or without the leading {@code v}, so both the
     * release feed and the version printed by the jar itself parse the same way.
     */
    private static final Pattern TAG =
            Pattern.compile("^v?(\\d+)\\.(\\d+)\\.(\\d+)(?:-([0-9A-Za-z.-]+))?$");

    /** Parses a tag or version string, or empty if it is not one this tool would publish. */
    public static Optional<Version> parse(String text) {
        if (text == null) {
            return Optional.empty();
        }
        var matcher = TAG.matcher(text.strip());
        if (!matcher.matches()) {
            return Optional.empty();
        }
        return Optional.of(new Version(
                Integer.parseInt(matcher.group(1)),
                Integer.parseInt(matcher.group(2)),
                Integer.parseInt(matcher.group(3)),
                matcher.group(4)));
    }

    /** Whether this is a plain release rather than an alpha, beta or release candidate. */
    public boolean isStable() {
        return suffix == null;
    }

    @Override
    public int compareTo(Version other) {
        int order = Long.compare(
                (major * 1_000_000L) + (minor * 1_000L) + patch,
                (other.major * 1_000_000L) + (other.minor * 1_000L) + other.patch);
        if (order != 0) {
            return order;
        }
        if (suffix == null) {
            return other.suffix == null ? 0 : 1;
        }
        if (other.suffix == null) {
            return -1;
        }
        return compareSuffixes(suffix, other.suffix);
    }

    /**
     * Compares prerelease suffixes the way semver orders identifiers: runs of digits compare
     * numerically (rc10 > rc2), runs of text lexically, and a numeric run sorts below a text run.
     */
    private static int compareSuffixes(String left, String right) {
        List<String> leftRuns = runs(left);
        List<String> rightRuns = runs(right);
        int shared = Math.min(leftRuns.size(), rightRuns.size());
        for (int i = 0; i < shared; i++) {
            String l = leftRuns.get(i);
            String r = rightRuns.get(i);
            boolean leftNumeric = l.chars().allMatch(Character::isDigit);
            boolean rightNumeric = r.chars().allMatch(Character::isDigit);
            int order;
            if (leftNumeric && rightNumeric) {
                order = Long.compare(Long.parseLong(l), Long.parseLong(r));
            } else if (leftNumeric) {
                order = -1; // semver: a numeric identifier always sorts below a text one
            } else if (rightNumeric) {
                order = 1;
            } else {
                order = l.compareTo(r);
            }
            if (order != 0) {
                return order;
            }
        }
        return Integer.compare(leftRuns.size(), rightRuns.size());
    }

    /** Splits a suffix into its consecutive digit and non-digit runs: {@code rc10} → rc, 10. */
    private static List<String> runs(String text) {
        List<String> parts = new ArrayList<>();
        int start = 0;
        boolean digits = Character.isDigit(text.charAt(0));
        for (int i = 1; i < text.length(); i++) {
            boolean currentIsDigit = Character.isDigit(text.charAt(i));
            if (currentIsDigit != digits) {
                parts.add(text.substring(start, i));
                start = i;
                digits = currentIsDigit;
            }
        }
        parts.add(text.substring(start));
        return parts;
    }

    @Override
    public String toString() {
        return suffix == null
                ? "%d.%d.%d".formatted(major, minor, patch)
                : "%d.%d.%d-%s".formatted(major, minor, patch, suffix);
    }
}
