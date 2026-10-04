/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.tools.provenance;

import java.util.ArrayList;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.plugin.ConfigManager;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.RevaInternalServiceRegistry;
import reva.util.SchemaUtil;

/**
 * Read-only bridge between decompiler markup, high P-code, SSA varnodes, and
 * machine addresses.
 *
 * <p>This provider deliberately reports Ghidra's provenance links instead of
 * reconstructing or guessing source expressions. A decompiler line is contextual:
 * only token-level links with an associated address, PcodeOp, or Varnode are
 * authoritative semantic provenance.</p>
 */
public class SemanticProvenanceToolProvider extends AbstractToolProvider {
    private record TokenLineContext(ClangLine line, int tokenIndex) {}

    private static final int DEFAULT_DECOMPILER_TIMEOUT_SECS = 30;
    private static final int DEFAULT_MAX_TOKENS = 64;
    private static final int HARD_MAX_TOKENS = 256;
    private static final int DEFAULT_MAX_ARGUMENTS = 32;
    private static final int HARD_MAX_ARGUMENTS = 128;
    private static final int HARD_MAX_ADDRESS_PCODE = 128;
    private static final int HARD_MAX_RELATED_TOKENS = 32;

    private static final String PROVENANCE_SEMANTICS =
        "Direct token addresses, PcodeOp links, Varnode links, HighVariable links, and " +
        "HighSymbol links are facts exposed by Ghidra's decompiler model. Decompiled line " +
        "text is contextual and must not be treated as a one-to-one machine mapping when " +
        "multiple tokens or operations share a line.";

    public SemanticProvenanceToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerGetDecompilerProvenanceTool();
        registerGetCallsiteSemanticsTool();
    }

    private void registerGetDecompilerProvenanceTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("function",
            SchemaUtil.stringProperty("Function name, symbol, or address to decompile"));
        properties.put("address",
            SchemaUtil.stringProperty(
                "Optional machine address or symbol inside the function. When supplied, only " +
                "tokens directly linked to the containing instruction are returned."));
        properties.put("displayLine",
            Map.of("type", "integer",
                "description", "Optional 1-based line number from ReVa get-decompilation output."));
        properties.put("tokenText",
            SchemaUtil.stringProperty(
                "Optional case-sensitive token-text substring. Multiple selectors are ANDed."));
        properties.put("maxTokens",
            SchemaUtil.integerPropertyWithDefault(
                "Maximum matching tokens to return (hard cap 256)", DEFAULT_MAX_TOKENS));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-decompiler-provenance")
            .title("Get Decompiler Provenance")
            .description("Link selected decompiler tokens to Ghidra HighFunction facts: exact token " +
                "addresses, P-code operations, SSA varnodes, HighVariables, and HighSymbols. " +
                "Requires at least one selector: address, displayLine, or tokenText. Read-only.")
            .inputSchema(createSchema(properties, List.of("programPath", "function")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Function function =
                getFunctionFromArgs(request.arguments(), program, "function");

            String addressText =
                normalizeOptional(getOptionalString(request, "address", null));
            Integer displayLine =
                getOptionalInteger(request.arguments(), "displayLine", null);
            String tokenText =
                normalizeOptional(getOptionalString(request, "tokenText", null));

            if (addressText == null && displayLine == null && tokenText == null) {
                return createErrorResult(
                    "At least one selector is required: address, displayLine, or tokenText");
            }
            if (displayLine != null && displayLine <= 0) {
                return createErrorResult("displayLine must be greater than zero");
            }

            int maxTokens = boundedPositive(
                getOptionalInt(request, "maxTokens", DEFAULT_MAX_TOKENS),
                HARD_MAX_TOKENS, "maxTokens");

            Address requestedAddress = null;
            Address canonicalAddress = null;
            if (addressText != null) {
                requestedAddress =
                    AddressUtil.resolveAddressOrSymbol(program, addressText);
                if (requestedAddress == null) {
                    return createErrorResult(
                        "Invalid address or symbol: " + addressText);
                }

                Instruction instruction =
                    program.getListing().getInstructionContaining(requestedAddress);
                canonicalAddress =
                    instruction != null ? instruction.getAddress() : requestedAddress;

                if (!function.getBody().contains(canonicalAddress)) {
                    return createErrorResult("Address " +
                        AddressUtil.formatAddress(requestedAddress) +
                        " is not inside function " + function.getName());
                }
            }

            followRead(program,
                canonicalAddress != null ? canonicalAddress : function.getEntryPoint());

            DecompInterface decompiler = createConfiguredDecompiler(program);
            if (decompiler == null) {
                return createErrorResult("Failed to initialize decompiler");
            }

            try {
                DecompileResults results = decompileFunction(decompiler, function);
                if (results == null || !results.decompileCompleted()) {
                    String error =
                        results != null ? results.getErrorMessage() : "unknown";
                    return createErrorResult("Decompilation failed: " + error);
                }

                HighFunction highFunction = results.getHighFunction();
                ClangTokenGroup markup = results.getCCodeMarkup();
                if (highFunction == null || markup == null) {
                    return createErrorResult(
                        "Decompiler did not return both HighFunction and C-code markup");
                }

                List<ClangLine> lines = DecompilerUtils.toLines(markup);
                Map<ClangLine, Integer> displayLines =
                    buildDisplayLineMap(results, lines);
                List<Map<String, Object>> matches = new ArrayList<>();
                int matchedCount = 0;

                for (ClangLine line : lines) {
                    int currentDisplayLine =
                        displayLineNumber(line, displayLines);
                    if (displayLine != null &&
                        currentDisplayLine != displayLine.intValue()) {
                        continue;
                    }

                    List<ClangToken> lineTokens = line.getAllTokens();
                    for (int tokenIndex = 0;
                            tokenIndex < lineTokens.size(); tokenIndex++) {
                        ClangToken token = lineTokens.get(tokenIndex);

                        if (tokenText != null) {
                            String text = token.getText();
                            if (text == null || !text.contains(tokenText)) {
                                continue;
                            }
                        }

                        if (canonicalAddress != null &&
                            !tokenDirectlyCoversAddress(token, canonicalAddress)) {
                            continue;
                        }

                        matchedCount++;
                        if (matches.size() < maxTokens) {
                            matches.add(serializeToken(
                                token, highFunction, program, line, tokenIndex,
                                displayLines));
                        }
                    }
                }

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("programPath",
                    program.getDomainFile().getPathname());
                result.put("function", function.getName());
                result.put("functionAddress",
                    AddressUtil.formatAddress(function.getEntryPoint()));
                result.put("provenanceSemantics", PROVENANCE_SEMANTICS);
                result.put("displayLineNumbering",
                    "1-based line number matched against the actual DecompiledFunction.getC() " +
                    "rendering used by ReVa get-decompilation; no fixed Clang-line offset is assumed.");

                Map<String, Object> selectors = new LinkedHashMap<>();
                selectors.put("address", addressText);
                selectors.put("displayLine", displayLine);
                selectors.put("tokenText", tokenText);
                result.put("selectors", selectors);

                if (requestedAddress != null) {
                    result.put("requestedAddress",
                        AddressUtil.formatAddress(requestedAddress));
                    result.put("canonicalInstructionAddress",
                        AddressUtil.formatAddress(canonicalAddress));

                    List<Map<String, Object>> addressOps =
                        serializePcodeAtAddress(
                            highFunction, canonicalAddress, program);
                    result.put("highPcodeAtAddress", addressOps);
                    result.put("highPcodeAtAddressTruncated",
                        hasMorePcodeAtAddress(
                            highFunction, canonicalAddress, addressOps.size()));
                }

                result.put("matchedTokenCount", matchedCount);
                result.put("returnedTokenCount", matches.size());
                result.put("tokens", matches);
                result.put("truncated", matchedCount > matches.size());

                if (matchedCount == 0) {
                    result.put("note",
                        "No directly linked decompiler token matched all selectors. " +
                        "This is not evidence that the machine address has no High P-code; " +
                        "inspect highPcodeAtAddress when an address selector was supplied.");
                }

                return createJsonResult(result);
            }
            finally {
                decompiler.dispose();
            }
        });
    }

    private void registerGetCallsiteSemanticsTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("callsite",
            SchemaUtil.stringProperty(
                "Address or symbol resolving to a machine call instruction"));
        properties.put("maxArguments",
            SchemaUtil.integerPropertyWithDefault(
                "Maximum High P-code call arguments to return (hard cap 128)",
                DEFAULT_MAX_ARGUMENTS));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-callsite-semantics")
            .title("Get Call-site Semantics")
            .description("Inspect one machine call site through Ghidra's decompiler model. " +
                "Returns the machine instruction, CALL/CALLIND High P-code, resolved direct " +
                "target when available, decompiler statement context, and bounded argument " +
                "varnode/producer provenance. Does not guess ABI register placement or execute code.")
            .inputSchema(createSchema(properties,
                List.of("programPath", "callsite")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address requestedCallsite =
                getAddressFromArgs(request, program, "callsite");

            Instruction instruction =
                program.getListing().getInstructionContaining(requestedCallsite);
            if (instruction == null) {
                return createErrorResult("No instruction contains " +
                    AddressUtil.formatAddress(requestedCallsite));
            }

            Address callsite = instruction.getAddress();
            Function caller =
                program.getFunctionManager().getFunctionContaining(callsite);
            if (caller == null) {
                return createErrorResult("No function contains call site " +
                    AddressUtil.formatAddress(callsite));
            }

            int maxArguments = boundedPositive(
                getOptionalInt(request, "maxArguments", DEFAULT_MAX_ARGUMENTS),
                HARD_MAX_ARGUMENTS, "maxArguments");

            followRead(program, callsite);

            DecompInterface decompiler = createConfiguredDecompiler(program);
            if (decompiler == null) {
                return createErrorResult("Failed to initialize decompiler");
            }

            try {
                DecompileResults results = decompileFunction(decompiler, caller);
                if (results == null || !results.decompileCompleted()) {
                    String error =
                        results != null ? results.getErrorMessage() : "unknown";
                    return createErrorResult("Decompilation failed: " + error);
                }

                HighFunction highFunction = results.getHighFunction();
                ClangTokenGroup markup = results.getCCodeMarkup();
                if (highFunction == null || markup == null) {
                    return createErrorResult(
                        "Decompiler did not return both HighFunction and C-code markup");
                }

                List<ClangLine> lines = DecompilerUtils.toLines(markup);
                Map<ClangToken, TokenLineContext> tokenLineContexts =
                    buildTokenLineContexts(lines);
                Map<ClangLine, Integer> displayLines =
                    buildDisplayLineMap(results, lines);

                List<PcodeOpAST> callOps = new ArrayList<>();
                List<String> opcodesAtAddress = new ArrayList<>();
                Iterator<PcodeOpAST> iterator =
                    highFunction.getPcodeOps(callsite);

                while (iterator.hasNext()) {
                    PcodeOpAST op = iterator.next();
                    opcodesAtAddress.add(op.getMnemonic());
                    if (op.getOpcode() == PcodeOp.CALL ||
                        op.getOpcode() == PcodeOp.CALLIND) {
                        callOps.add(op);
                    }
                }

                if (callOps.isEmpty()) {
                    return createErrorResult(
                        "No decompiler CALL or CALLIND operation at " +
                        AddressUtil.formatAddress(callsite) +
                        "; High P-code operations there: " + opcodesAtAddress);
                }

                List<Map<String, Object>> calls = new ArrayList<>();
                for (PcodeOp callOp : callOps) {
                    calls.add(serializeCall(
                        callOp, markup, highFunction, program, maxArguments,
                        tokenLineContexts, displayLines));
                }

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("programPath",
                    program.getDomainFile().getPathname());
                result.put("caller", caller.getName());
                result.put("callerAddress",
                    AddressUtil.formatAddress(caller.getEntryPoint()));
                result.put("requestedCallsite",
                    AddressUtil.formatAddress(requestedCallsite));
                result.put("callsite", AddressUtil.formatAddress(callsite));
                result.put("instruction", instruction.toString());
                result.put("flowType", instruction.getFlowType().toString());
                result.put("provenanceSemantics", PROVENANCE_SEMANTICS);
                result.put("displayLineNumbering",
                    "1-based line number matched against the actual DecompiledFunction.getC() " +
                    "rendering used by ReVa get-decompilation; no fixed Clang-line offset is assumed.");
                result.put("argumentSemantics",
                    "Arguments are High P-code CALL/CALLIND inputs after input 0 " +
                    "(the call target). relatedDecompilerTokens are direct Varnode " +
                    "or shared HighVariable links only; they are evidence, not reconstructed " +
                    "source expressions. producer is the argument Varnode's immediate " +
                    "defining High P-code operation when available.");
                result.put("callOperationCount", calls.size());
                result.put("calls", calls);
                return createJsonResult(result);
            }
            finally {
                decompiler.dispose();
            }
        });
    }

    private Map<String, Object> serializeCall(
            PcodeOp callOp, ClangTokenGroup markup,
            HighFunction highFunction, Program program, int maxArguments,
            Map<ClangToken, TokenLineContext> tokenLineContexts,
            Map<ClangLine, Integer> displayLines) {
        Map<String, Object> call = new LinkedHashMap<>();
        call.put("opcode", callOp.getMnemonic());
        call.put("direct", callOp.getOpcode() == PcodeOp.CALL);
        call.put("pcode", serializePcodeOp(callOp, program));

        Varnode target =
            callOp.getNumInputs() > 0 ? callOp.getInput(0) : null;
        call.put("target", serializeCallTarget(target, callOp, program));

        ClangStatement statement = findStatementForOp(markup, callOp);
        if (statement != null) {
            call.put("statementText", statement.toString());
            call.put("statementLines",
                statementDisplayLines(
                    statement, tokenLineContexts, displayLines));
            call.put("statementMinAddress",
                statement.getMinAddress() != null
                    ? AddressUtil.formatAddress(statement.getMinAddress()) : null);
            call.put("statementMaxAddress",
                statement.getMaxAddress() != null
                    ? AddressUtil.formatAddress(statement.getMaxAddress()) : null);
        }
        else {
            call.put("statementText", null);
            call.put("statementLines", List.of());
            call.put("statementMinAddress", null);
            call.put("statementMaxAddress", null);
        }

        int argumentCount = Math.max(0, callOp.getNumInputs() - 1);
        int returnedCount = Math.min(argumentCount, maxArguments);
        List<Map<String, Object>> arguments =
            new ArrayList<>(returnedCount);

        for (int index = 0; index < returnedCount; index++) {
            Varnode argument = callOp.getInput(index + 1);
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("index", index);
            info.put("varnode", serializeVarnode(argument, program));
            info.put("highVariable",
                serializeHighVariable(
                    argument != null ? argument.getHigh() : null, program));
            info.put("producer",
                argument != null && argument.getDef() != null
                    ? serializePcodeOp(argument.getDef(), program) : null);

            int relatedCount =
                countRelatedDecompilerTokens(statement, argument);
            List<Map<String, Object>> related =
                findRelatedDecompilerTokens(
                    statement, argument, highFunction, program,
                    HARD_MAX_RELATED_TOKENS, tokenLineContexts,
                    displayLines);
            info.put("relatedDecompilerTokens", related);
            info.put("relatedDecompilerTokenCount", relatedCount);
            info.put("relatedDecompilerTokensTruncated",
                relatedCount > related.size());
            arguments.add(info);
        }

        call.put("argumentCount", argumentCount);
        call.put("returnedArgumentCount", arguments.size());
        call.put("arguments", arguments);
        call.put("argumentsTruncated",
            argumentCount > arguments.size());

        if (argumentCount > arguments.size()) {
            call.put("note",
                "Argument output stopped at maxArguments; increase the bound to inspect more.");
        }

        return call;
    }

    private static Map<String, Object> serializeCallTarget(
            Varnode target, PcodeOp callOp, Program program) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("varnode", serializeVarnode(target, program));

        if (callOp.getOpcode() != PcodeOp.CALL ||
            target == null || target.getAddress() == null) {
            info.put("resolved", false);
            info.put("address", null);
            info.put("name", null);
            info.put("prototype", null);
            info.put("thunk", null);
            info.put("external", null);
            info.put("symbol", null);
            return info;
        }

        Address address = target.getAddress();
        info.put("address", AddressUtil.formatAddress(address));

        FunctionManager manager = program.getFunctionManager();
        Function function = manager.getFunctionAt(address);
        if (function == null) {
            function = manager.getReferencedFunction(address);
        }

        Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
        info.put("symbol", symbol != null ? symbol.getName() : null);

        if (function != null) {
            info.put("resolved", true);
            info.put("name", function.getName());
            info.put("prototype",
                function.getPrototypeString(false, true));
            info.put("thunk", function.isThunk());
            info.put("external", function.isExternal());
        }
        else {
            info.put("resolved", symbol != null);
            info.put("name", symbol != null ? symbol.getName() : null);
            info.put("prototype", null);
            info.put("thunk", null);
            info.put("external", null);
        }

        return info;
    }

    private static List<Map<String, Object>> findRelatedDecompilerTokens(
            ClangStatement statement, Varnode argument,
            HighFunction highFunction, Program program, int maxTokens,
            Map<ClangToken, TokenLineContext> tokenLineContexts,
            Map<ClangLine, Integer> displayLines) {
        if (statement == null || argument == null) {
            return List.of();
        }

        List<Map<String, Object>> related = new ArrayList<>();
        Iterator<ClangToken> iterator = statement.tokenIterator(true);
        HighVariable argumentHigh = argument.getHigh();

        while (iterator.hasNext() && related.size() < maxTokens) {
            ClangToken token = iterator.next();
            Varnode tokenVarnode = token.getVarnode();
            HighVariable tokenHigh = token.getHighVariable();

            String matchKind = null;
            if (tokenVarnode == argument) {
                matchKind = "varnode-exact";
            }
            else if (argumentHigh != null &&
                tokenHigh == argumentHigh) {
                matchKind = "high-variable";
            }

            if (matchKind != null) {
                TokenLineContext context =
                    tokenLineContexts.get(token);
                ClangLine line =
                    context != null ? context.line() : token.getLineParent();
                int tokenIndex =
                    context != null ? context.tokenIndex()
                        : (line != null ? line.indexOfToken(token) : -1);
                Map<String, Object> info = serializeToken(
                    token, highFunction, program, line, tokenIndex,
                    displayLines);
                info.put("matchKind", matchKind);
                related.add(info);
            }
        }

        return related;
    }

    private static int countRelatedDecompilerTokens(
            ClangStatement statement, Varnode argument) {
        if (statement == null || argument == null) {
            return 0;
        }

        int count = 0;
        HighVariable argumentHigh = argument.getHigh();
        Iterator<ClangToken> iterator = statement.tokenIterator(true);

        while (iterator.hasNext()) {
            ClangToken token = iterator.next();
            if (token.getVarnode() == argument ||
                (argumentHigh != null &&
                    token.getHighVariable() == argumentHigh)) {
                count++;
            }
        }

        return count;
    }

    private static ClangStatement findStatementForOp(
            ClangNode node, PcodeOp target) {
        if (node instanceof ClangStatement statement) {
            if (samePcodeOp(statement.getPcodeOp(), target)) {
                return statement;
            }

            Iterator<ClangToken> tokens = statement.tokenIterator(true);
            while (tokens.hasNext()) {
                if (samePcodeOp(tokens.next().getPcodeOp(), target)) {
                    return statement;
                }
            }
        }

        for (int i = 0; i < node.numChildren(); i++) {
            ClangStatement found =
                findStatementForOp(node.Child(i), target);
            if (found != null) {
                return found;
            }
        }

        return null;
    }

    private static boolean samePcodeOp(PcodeOp left, PcodeOp right) {
        if (left == right) {
            return true;
        }
        if (left == null || right == null ||
            left.getOpcode() != right.getOpcode() ||
            left.getSeqnum() == null || right.getSeqnum() == null) {
            return false;
        }
        return left.getSeqnum().equals(right.getSeqnum());
    }

    private static List<Integer> statementDisplayLines(
            ClangStatement statement,
            Map<ClangToken, TokenLineContext> tokenLineContexts,
            Map<ClangLine, Integer> displayLines) {
        Set<Integer> lines = new LinkedHashSet<>();
        Iterator<ClangToken> iterator = statement.tokenIterator(true);

        while (iterator.hasNext()) {
            ClangToken token = iterator.next();
            TokenLineContext context =
                tokenLineContexts.get(token);
            ClangLine line =
                context != null ? context.line() : token.getLineParent();
            if (line != null) {
                lines.add(displayLineNumber(line, displayLines));
            }
        }

        return new ArrayList<>(lines);
    }

    private static Map<ClangToken, TokenLineContext> buildTokenLineContexts(
            List<ClangLine> lines) {
        Map<ClangToken, TokenLineContext> contexts =
            new IdentityHashMap<>();

        for (ClangLine line : lines) {
            List<ClangToken> tokens = line.getAllTokens();
            for (int tokenIndex = 0;
                    tokenIndex < tokens.size(); tokenIndex++) {
                contexts.put(
                    tokens.get(tokenIndex),
                    new TokenLineContext(line, tokenIndex));
            }
        }

        return contexts;
    }

    private static Map<String, Object> serializeToken(
            ClangToken token, HighFunction highFunction,
            Program program, ClangLine line, int lineTokenIndex,
            Map<ClangLine, Integer> displayLines) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("text", token.getText());
        info.put("tokenClass", token.getClass().getSimpleName());
        info.put("syntaxType", token.getSyntaxType());

        if (line != null) {
            info.put("clangLineNumber", line.getLineNumber());
            info.put("displayLineNumber",
                displayLineNumber(line, displayLines));
            info.put("lineTokenIndex", lineTokenIndex);
            info.put("lineText", renderLine(line));
        }
        else {
            info.put("clangLineNumber", null);
            info.put("displayLineNumber", null);
            info.put("lineTokenIndex", lineTokenIndex);
            info.put("lineText", null);
        }

        Address minAddress = token.getMinAddress();
        Address maxAddress = token.getMaxAddress();
        info.put("directAddressLinked", minAddress != null);
        info.put("minAddress",
            minAddress != null
                ? AddressUtil.formatAddress(minAddress) : null);
        info.put("maxAddress",
            maxAddress != null
                ? AddressUtil.formatAddress(maxAddress)
                : (minAddress != null
                    ? AddressUtil.formatAddress(minAddress) : null));

        PcodeOp pcodeOp = token.getPcodeOp();
        info.put("pcodeOp",
            pcodeOp != null
                ? serializePcodeOp(pcodeOp, program) : null);

        Varnode varnode = token.getVarnode();
        info.put("varnode",
            serializeVarnode(varnode, program));
        info.put("definingPcodeOp",
            varnode != null && varnode.getDef() != null
                ? serializePcodeOp(varnode.getDef(), program) : null);

        HighVariable highVariable = token.getHighVariable();
        info.put("highVariable",
            serializeHighVariable(highVariable, program));

        HighSymbol highSymbol = token.getHighSymbol(highFunction);
        info.put("highSymbol",
            serializeHighSymbol(highSymbol));

        return info;
    }

    private static Map<String, Object> serializeHighVariable(
            HighVariable variable, Program program) {
        if (variable == null) {
            return null;
        }

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", variable.getName());
        info.put("class", variable.getClass().getSimpleName());
        info.put("dataType",
            variable.getDataType() != null
                ? variable.getDataType().getDisplayName() : null);
        info.put("offsetIntoSymbol", variable.getOffset());

        Varnode representative = variable.getRepresentative();
        info.put("representative",
            serializeVarnode(representative, program));
        info.put("size",
            representative != null ? representative.getSize() : null);

        HighSymbol symbol = variable.getSymbol();
        info.put("symbolName",
            symbol != null ? symbol.getName() : null);
        return info;
    }

    private static Map<String, Object> serializeHighSymbol(
            HighSymbol symbol) {
        if (symbol == null) {
            return null;
        }

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", symbol.getName());
        info.put("id", symbol.getId());
        info.put("dataType",
            symbol.getDataType() != null
                ? symbol.getDataType().getDisplayName() : null);
        info.put("parameter", symbol.isParameter());
        info.put("parameterIndex",
            symbol.isParameter()
                ? symbol.getCategoryIndex() : null);
        info.put("global", symbol.isGlobal());
        info.put("thisPointer", symbol.isThisPointer());
        info.put("hiddenReturn", symbol.isHiddenReturn());
        return info;
    }

    private static Map<String, Object> serializePcodeOp(
            PcodeOp op, Program program) {
        if (op == null) {
            return null;
        }

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("mnemonic", op.getMnemonic());

        if (op.getSeqnum() != null) {
            Address target = op.getSeqnum().getTarget();
            info.put("sequenceAddress",
                target != null
                    ? AddressUtil.formatAddress(target) : null);
            info.put("sequenceOrder", op.getSeqnum().getOrder());
        }
        else {
            info.put("sequenceAddress", null);
            info.put("sequenceOrder", null);
        }

        info.put("output",
            serializeVarnode(op.getOutput(), program));

        List<Map<String, Object>> inputs = new ArrayList<>();
        for (int i = 0; i < op.getNumInputs(); i++) {
            inputs.add(
                serializeVarnode(op.getInput(i), program));
        }
        info.put("inputs", inputs);
        return info;
    }

    private static Map<String, Object> serializeVarnode(
            Varnode node, Program program) {
        if (node == null) {
            return null;
        }

        Map<String, Object> info = new LinkedHashMap<>();
        info.put("repr", node.toString(program.getLanguage()));
        info.put("size", node.getSize());

        Address address = node.getAddress();
        info.put("address",
            address != null ? address.toString() : null);
        info.put("space",
            address != null
                ? address.getAddressSpace().getName() : null);
        info.put("offset",
            address != null ? address.getOffset() : null);

        Register register = program.getRegister(node);
        info.put("registerName",
            register != null ? register.getName() : null);

        String kind;
        if (node.isConstant()) {
            kind = "constant";
        }
        else if (node.isRegister()) {
            kind = "register";
        }
        else if (address != null && address.isStackAddress()) {
            kind = "stack";
        }
        else if (node.isUnique()) {
            kind = "unique";
        }
        else if (node.isAddress()) {
            kind = "memory";
        }
        else {
            kind = "other";
        }
        info.put("kind", kind);

        info.put("constant", node.isConstant());
        info.put("input", node.isInput());
        info.put("addressTied", node.isAddrTied());
        info.put("persistent", node.isPersistent());
        info.put("unaffected", node.isUnaffected());
        info.put("free", node.isFree());

        if (node.isConstant()) {
            info.put("value",
                "0x" + Long.toUnsignedString(node.getOffset(), 16));
        }

        return info;
    }

    private static List<Map<String, Object>> serializePcodeAtAddress(
            HighFunction highFunction, Address address, Program program) {
        List<Map<String, Object>> ops = new ArrayList<>();
        Iterator<PcodeOpAST> iterator =
            highFunction.getPcodeOps(address);

        while (iterator.hasNext() &&
            ops.size() < HARD_MAX_ADDRESS_PCODE) {
            ops.add(serializePcodeOp(iterator.next(), program));
        }

        return ops;
    }

    private static boolean hasMorePcodeAtAddress(
            HighFunction highFunction, Address address, int returnedCount) {
        int count = 0;
        Iterator<PcodeOpAST> iterator =
            highFunction.getPcodeOps(address);

        while (iterator.hasNext()) {
            iterator.next();
            count++;
            if (count > returnedCount) {
                return true;
            }
        }

        return false;
    }

    private static boolean tokenDirectlyCoversAddress(
            ClangToken token, Address address) {
        Address min = token.getMinAddress();
        if (min == null || address == null ||
            min.getAddressSpace() != address.getAddressSpace()) {
            return false;
        }

        Address max = token.getMaxAddress();
        if (max == null) {
            max = min;
        }

        return min.compareTo(address) <= 0 &&
            max.compareTo(address) >= 0;
    }

    private static String renderLine(ClangLine line) {
        StringBuilder text =
            new StringBuilder(line.getIndentString());
        for (ClangToken token : line.getAllTokens()) {
            if (token.getText() != null) {
                text.append(token.getText());
            }
        }
        return text.toString();
    }

    private static int displayLineNumber(
            ClangLine line, Map<ClangLine, Integer> displayLines) {
        Integer mapped = displayLines.get(line);
        return mapped != null ? mapped : line.getLineNumber();
    }

    private static Map<ClangLine, Integer> buildDisplayLineMap(
            DecompileResults results, List<ClangLine> clangLines) {
        Map<ClangLine, Integer> mapping =
            new IdentityHashMap<>();

        if (results == null ||
            results.getDecompiledFunction() == null) {
            for (ClangLine line : clangLines) {
                mapping.put(line, line.getLineNumber());
            }
            return mapping;
        }

        String decompilation =
            results.getDecompiledFunction().getC();
        if (decompilation == null) {
            decompilation = "";
        }

        String[] renderedLines =
            decompilation.split("\\R", -1);
        int searchFrom = 0;

        for (ClangLine clangLine : clangLines) {
            String expected = renderLine(clangLine);
            int matchedIndex =
                findRenderedLine(
                    renderedLines, expected, searchFrom);

            if (matchedIndex < 0) {
                mapping.put(
                    clangLine, clangLine.getLineNumber());
                continue;
            }

            mapping.put(clangLine, matchedIndex + 1);
            searchFrom = matchedIndex + 1;
        }

        return mapping;
    }

    private static int findRenderedLine(
            String[] renderedLines, String expected, int searchFrom) {
        for (int i = searchFrom; i < renderedLines.length; i++) {
            if (renderedLines[i].equals(expected)) {
                return i;
            }
        }

        String normalizedExpected = expected.strip();
        for (int i = searchFrom; i < renderedLines.length; i++) {
            if (renderedLines[i].strip().equals(normalizedExpected)) {
                return i;
            }
        }

        return -1;
    }

    private DecompInterface createConfiguredDecompiler(
            Program program) {
        DecompInterface decompiler = new DecompInterface();
        decompiler.toggleCCode(true);
        decompiler.toggleSyntaxTree(true);
        decompiler.setSimplificationStyle("decompile");

        if (!decompiler.openProgram(program)) {
            return null;
        }

        return decompiler;
    }

    private DecompileResults decompileFunction(
            DecompInterface decompiler, Function function) {
        int timeout = getDecompilerTimeout();
        TaskMonitor monitor =
            TimeoutTaskMonitor.timeoutIn(timeout, TimeUnit.SECONDS);
        return decompiler.decompileFunction(
            function, timeout, monitor);
    }

    private int getDecompilerTimeout() {
        try {
            ConfigManager config =
                RevaInternalServiceRegistry.getService(
                    ConfigManager.class);
            if (config != null) {
                return config.getDecompilerTimeoutSeconds();
            }
        }
        catch (Exception e) {
            // Fall through to the bounded default.
        }

        return DEFAULT_DECOMPILER_TIMEOUT_SECS;
    }

    private static String normalizeOptional(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }

    private static int boundedPositive(
            int value, int hardMax, String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(
                name + " must be greater than zero");
        }
        return Math.min(value, hardMax);
    }
}
