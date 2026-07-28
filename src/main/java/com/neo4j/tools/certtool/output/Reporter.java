package com.neo4j.tools.certtool.output;

import java.io.PrintStream;

/** Prints progress and warnings, honouring {@code --quiet}. */
public final class Reporter {

    private final PrintStream out;
    private final PrintStream err;
    private final boolean quiet;

    public Reporter(PrintStream out, PrintStream err, boolean quiet) {
        this.out = out;
        this.err = err;
        this.quiet = quiet;
    }

    /** Informational output, suppressed by {@code --quiet}. */
    public void info(String message) {
        if (!quiet) {
            out.println(message);
        }
    }

    public void info(String format, Object... arguments) {
        info(format.formatted(arguments));
    }

    /** Output the user asked for, printed even when quiet. */
    public void print(String message) {
        out.println(message);
    }

    /** A problem worth surfacing that does not stop the run. Always printed. */
    public void warn(String message) {
        err.println("Warning: " + message);
    }

    public void warn(String format, Object... arguments) {
        warn(format.formatted(arguments));
    }

    public void blankLine() {
        info("");
    }
}
