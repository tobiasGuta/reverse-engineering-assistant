/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.util;

import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;

/**
 * Maps Ghidra Clang tokens to the physical 1-based lines of
 * DecompiledFunction.getC() (the lines exposed by ReVa get-decompilation).
 *
 * Ghidra PrettyPrinter emits ClangLines in order, adding one line break after
 * each; embedded token newlines create additional physical lines. A Clang
 * ordinal or a greedy text match is not a valid fallback. If the physical
 * rendered line count cannot be reconciled, return no mapping.
 */
public final class DecompilationDisplayLines {
    private DecompilationDisplayLines() {}

    public static Map<ClangLine, Integer> map(
            String renderedC, List<ClangLine> clangLines) {
        Map<ClangLine, Integer> mapping = new IdentityHashMap<>();
        if (renderedC == null || clangLines == null) {
            return mapping;
        }

        int physicalLine = 1;
        for (ClangLine line : clangLines) {
            mapping.put(line, physicalLine);
            physicalLine += 1; // PrettyPrinter emits a terminator per ClangLine
            for (ClangToken token : line.getAllTokens()) {
                physicalLine += countLineFeeds(token.getText());
            }
        }

        // Ghidra's pretty printer and get-decompilation split on LF. The
        // count must match before any displayed line is claimed.
        if (physicalLine - 1 != countLineFeeds(renderedC)) {
            mapping.clear();
        }
        return mapping;
    }

    public static Integer tokenLine(
            ClangLine line, int tokenIndex,
            Map<ClangLine, Integer> displayLines) {
        if (line == null || displayLines == null ||
            tokenIndex < 0 || tokenIndex >= line.getNumTokens()) {
            return null;
        }
        Integer start = displayLines.get(line);
        if (start == null) {
            return null;
        }
        int physicalLine = start;
        for (int i = 0; i < tokenIndex; i++) {
            physicalLine += countLineFeeds(line.getToken(i).getText());
        }
        return physicalLine;
    }

    private static int countLineFeeds(String value) {
        if (value == null) {
            return 0;
        }
        int count = 0;
        for (int i = 0; i < value.length(); i++) {
            if (value.charAt(i) == '\n') {
                count++;
            }
        }
        return count;
    }
}
