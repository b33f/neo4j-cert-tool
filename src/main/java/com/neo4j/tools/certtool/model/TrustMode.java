package com.neo4j.tools.certtool.model;

import java.util.Locale;
import java.util.stream.Collectors;

/**
 * How trust is established between cluster members.
 *
 * <p>The choice determines what ends up in each node's {@code trusted/} directory, and therefore
 * how much work it is to add or replace a node later.
 */
public enum TrustMode {

    /**
     * One offline root CA signs a leaf certificate for every node and scope. Only the root
     * certificate goes into each {@code trusted/} directory.
     */
    CA("ca", "Local root CA signs one leaf certificate per node"),

    /**
     * A root CA signs an intermediate CA, and the intermediate signs the leaves. The root can then
     * be kept fully offline and the intermediate rotated without redistributing trust.
     */
    INTERMEDIATE("intermediate", "Root CA -> intermediate CA -> leaf certificates"),

    /**
     * Every node gets a self-signed certificate, and every node's {@code trusted/} directory holds
     * a copy of every other node's certificate.
     */
    SELF_SIGNED("self-signed", "Self-signed certificate per node, cross-trusted");

    private final String optionValue;
    private final String summary;

    TrustMode(String optionValue, String summary) {
        this.optionValue = optionValue;
        this.summary = summary;
    }

    public String optionValue() {
        return optionValue;
    }

    public String summary() {
        return summary;
    }

    /** Whether this mode issues leaf certificates from a certificate authority. */
    public boolean usesCa() {
        return this != SELF_SIGNED;
    }

    public static TrustMode parse(String value) {
        String normalised = value.trim().toLowerCase(Locale.ROOT);
        for (TrustMode mode : values()) {
            if (mode.optionValue.equals(normalised)) {
                return mode;
            }
        }
        throw new IllegalArgumentException(
                "Unknown trust mode '" + value + "'. Choose one of: " + names());
    }

    public static String names() {
        return java.util.Arrays.stream(values())
                .map(TrustMode::optionValue)
                .collect(Collectors.joining(", "));
    }
}
