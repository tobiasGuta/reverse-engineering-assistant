/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.tools.dataflow;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Read-only, bounded two-boundary SSA investigation.
 *
 * A->B and B->C are distinct decompiler-positional candidates. The
 * intermediate SSA dependency is static and may traverse a phi merge;
 * it does not establish runtime reachability, aliasing, control-flow
 * feasibility, or equality of argument values across function frames.
 */
public final class TwoHopValueFlowToolProvider extends AbstractToolProvider {
    private static final int DEFAULT_MAX_OPS = 128;
    private static final int DEFAULT_REPORTED_OPS = 12;
    private static final int MAX_OPS = 500;
    private static final int MAX_CALL_ARGS = 128;
    private static final int MAX_SSA_SEEDS = 128;
    private static final int MAX_SECOND_HOP_CANDIDATES = 4;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 30;
    private static final String DISCLAIMER =
        "Static decompiler-derived candidates across at most TWO direct " +
        "call boundaries. Each function has independent SSA evidence; " +
        "there is NO proven runtime caller-to-callee value equivalence, " +
        "memory alias analysis, path feasibility, or execution.";

    public TwoHopValueFlowToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Ghidra project path"));
        properties.put("callsite", SchemaUtil.stringProperty(
            "First machine CALL instruction address"));
        properties.put("argumentIndex", SchemaUtil.integerProperty(
            "Zero-based High P-code CALL argument index"));
        properties.put("maxOperations", SchemaUtil.integerPropertyWithDefault(
            "Maximum observed SSA operations PER slice, 1..500", DEFAULT_MAX_OPS));
        properties.put("maxReportedOperations", SchemaUtil.integerPropertyWithDefault(
            "Maximum detailed records PER slice, 0..maxOperations",
            DEFAULT_REPORTED_OPS));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("trace-call-argument-two-hop")
            .title("Trace a Call Argument Through Two Candidate Boundaries")
            .description("Read-only, bounded static investigation of a call " +
                "argument through a known direct callee to its directly " +
                "called functions. No runtime-equivalence claims.")
            .inputSchema(createSchema(properties,
                List.of("programPath", "callsite", "argumentIndex")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address requested = getAddressFromArgs(request, program, "callsite");
            int argIndex = getInt(request, "argumentIndex");
            int limit = getOptionalInt(request, "maxOperations", DEFAULT_MAX_OPS);
            int reported = getOptionalInt(request,
                "maxReportedOperations", Math.min(DEFAULT_REPORTED_OPS, limit));
            if (argIndex < 0 || argIndex >= MAX_CALL_ARGS ||
                limit < 1 || limit > MAX_OPS ||
                reported < 0 || reported > limit) {
                return createErrorResult("Invalid argumentIndex (0..127), " +
                    "maxOperations (1..500), or maxReportedOperations " +
                    "(0..maxOperations)");
            }

            Instruction instruction =
                program.getListing().getInstructionContaining(requested);
            if (instruction == null || !instruction.getFlowType().isCall()) {
                return createErrorResult("callsite is not a machine CALL");
            }
            Address site = instruction.getAddress();
            Function caller = program.getFunctionManager()
                .getFunctionContaining(site);
            if (caller == null) {
                return createErrorResult("No caller contains callsite");
            }
            followRead(program, site);

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("callsite", AddressUtil.formatAddress(site));
            result.put("caller", identity(caller));
            result.put("argumentIndex", argIndex);
            result.put("maxOperationsPerSlice", limit);
            result.put("maxReportedOperationsPerSlice", reported);
            result.put("semantics", DISCLAIMER);
            result.put("firstBoundaryStatus", "unavailable");
            result.put("secondBoundaryStatus", "unavailable");
            result.put("candidateSecondHops", List.of());
            result.put("complete", false);

            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(false);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(program)) {
                decompiler.dispose();
                return finish(result, "unavailable_decompiler");
            }
            try {
                HighFunction callerHigh = decompile(decompiler, caller);
                if (callerHigh == null) {
                    return finish(result, "unavailable_caller_decompilation");
                }
                PcodeOpAST firstCall = uniqueCall(callerHigh, site);
                if (firstCall == null || firstCall.getOpcode() != PcodeOp.CALL) {
                    return finish(result, "unavailable_ambiguous_or_indirect_call");
                }
                int firstArgCount = firstCall.getNumInputs() - 1;
                if (firstArgCount < 0 || firstArgCount > MAX_CALL_ARGS ||
                    argIndex >= firstArgCount) {
                    return finish(result, "unavailable_argument_index_or_count");
                }
                Varnode originalArg = firstCall.getInput(argIndex + 1);
                if (originalArg == null) {
                    return finish(result, "unavailable_original_argument");
                }
                result.put("firstCallSequence",
                    firstCall.getSeqnum().toString());
                result.put("originalArgument", node(originalArg));

                BoundedDataFlowSlice.Result originalSlice =
                    BoundedDataFlowSlice.collect(List.of(originalArg),
                        BoundedDataFlowSlice.Direction.BACKWARD, limit);
                Map<String, Object> callerEvidence =
                    OneHopValueFlowToolProvider.sliceEvidence(caller,
                        List.of(originalArg), originalSlice,
                        BoundedDataFlowSlice.Direction.BACKWARD, reported);
                result.put("callerArgumentEvidence", callerEvidence);

                Function middle = directTarget(program, firstCall);
                if (middle == null || middle.isExternal() || middle.isThunk() ||
                    middle.getEntryPoint().equals(caller.getEntryPoint())) {
                    return finish(result, "unavailable_first_target");
                }
                result.put("intermediateFunction", identity(middle));
                if (!eligibleStoredPrototype(middle, firstArgCount, argIndex)) {
                    return finish(result, "ambiguous_first_prototype_or_storage");
                }
                HighFunction middleHigh = decompile(decompiler, middle);
                if (middleHigh == null) {
                    return finish(result, "unavailable_intermediate_decompilation");
                }
                List<Varnode> middleFormals =
                    formalInstances(middleHigh, middle, argIndex);
                if (middleFormals.isEmpty()) {
                    return finish(result, "unavailable_intermediate_ssa_formal");
                }
                result.put("firstBoundaryStatus",
                    "decompiler_positional_candidate");

                BoundedDataFlowSlice.Result middleForward =
                    BoundedDataFlowSlice.collect(middleFormals,
                        BoundedDataFlowSlice.Direction.FORWARD, limit);
                Map<String, Object> middleEvidence =
                    OneHopValueFlowToolProvider.sliceEvidence(middle,
                        middleFormals, middleForward,
                        BoundedDataFlowSlice.Direction.FORWARD, reported);
                result.put("intermediateFormalEvidence", middleEvidence);
                result.put("firstBoundaryComplete",
                    coverage(callerEvidence) && coverage(middleEvidence));

                List<ForwardedArgument> forwarded =
                    observedForwardedArguments(middleFormals,
                        middleForward.operations());
                result.put("observedForwardedArgumentCount", forwarded.size());
                if (forwarded.isEmpty()) {
                    result.put("secondBoundaryStatus",
                        middleForward.truncated()
                            ? "unavailable_no_forwarded_call_in_partial_slice"
                            : "unavailable_no_observed_forwarded_call");
                    return createJsonResult(result);
                }

                List<Map<String, Object>> candidates = new ArrayList<>();
                int rejected = 0;
                boolean complete = coverage(callerEvidence) &&
                    coverage(middleEvidence) && !middleForward.truncated();
                for (ForwardedArgument forwarding : forwarded) {
                    if (candidates.size() >= MAX_SECOND_HOP_CANDIDATES) {
                        break;
                    }
                    PcodeOp call = forwarding.call();
                    Map<String, Object> candidate = new LinkedHashMap<>();
                    candidate.put("callsite",
                        AddressUtil.formatAddress(call.getSeqnum().getTarget()));
                    candidate.put("callSequence", call.getSeqnum().toString());
                    candidate.put("argumentIndex", forwarding.argumentIndex());
                    candidate.put("intermediateDependency",
                        "observed_ssa_dependency_candidate");
                    candidate.put("boundaryStatus", "unavailable");
                    candidate.put("complete", false);
                    candidates.add(candidate);

                    Address nextSite = call.getSeqnum().getTarget();
                    Instruction nextMachineCall =
                        program.getListing().getInstructionAt(nextSite);
                    PcodeOpAST unique =
                        uniqueCall(middleHigh, nextSite);
                    if (nextMachineCall == null ||
                        !nextMachineCall.getFlowType().isCall() ||
                        unique == null || unique.getSeqnum() == null ||
                        !unique.getSeqnum().equals(call.getSeqnum()) ||
                        unique.getOpcode() != PcodeOp.CALL) {
                        candidate.put("boundaryStatus",
                            "unavailable_second_machine_call_or_pcode");
                        rejected++;
                        continue;
                    }
                    Function finalCallee = directTarget(program, call);
                    if (finalCallee == null || finalCallee.isExternal() ||
                        finalCallee.isThunk() ||
                        finalCallee.getEntryPoint().equals(middle.getEntryPoint()) ||
                        finalCallee.getEntryPoint().equals(caller.getEntryPoint())) {
                        candidate.put("boundaryStatus",
                            "unavailable_second_target_or_cycle");
                        rejected++;
                        continue;
                    }
                    candidate.put("callee", identity(finalCallee));
                    int secondArgCount = call.getNumInputs() - 1;
                    if (!eligibleStoredPrototype(finalCallee,
                            secondArgCount, forwarding.argumentIndex())) {
                        candidate.put("boundaryStatus",
                            "ambiguous_second_prototype_or_storage");
                        rejected++;
                        continue;
                    }
                    Varnode forwardedArg =
                        call.getInput(forwarding.argumentIndex() + 1);
                    BoundedDataFlowSlice.Result intermediateBackward =
                        BoundedDataFlowSlice.collect(List.of(forwardedArg),
                            BoundedDataFlowSlice.Direction.BACKWARD, limit);
                    Map<String, Object> intermediateArgEvidence =
                        OneHopValueFlowToolProvider.sliceEvidence(middle,
                            List.of(forwardedArg), intermediateBackward,
                            BoundedDataFlowSlice.Direction.BACKWARD, reported);
                    candidate.put("intermediateArgumentEvidence",
                        intermediateArgEvidence);
                    HighFunction finalHigh =
                        decompile(decompiler, finalCallee);
                    if (finalHigh == null) {
                        candidate.put("boundaryStatus",
                            "unavailable_second_callee_decompilation");
                        rejected++;
                        continue;
                    }
                    List<Varnode> finalFormals =
                        formalInstances(finalHigh, finalCallee,
                            forwarding.argumentIndex());
                    if (finalFormals.isEmpty()) {
                        candidate.put("boundaryStatus",
                            "unavailable_second_formal_ssa");
                        rejected++;
                        continue;
                    }
                    BoundedDataFlowSlice.Result finalForward =
                        BoundedDataFlowSlice.collect(finalFormals,
                            BoundedDataFlowSlice.Direction.FORWARD, limit);
                    Map<String, Object> finalEvidence =
                        OneHopValueFlowToolProvider.sliceEvidence(finalCallee,
                            finalFormals, finalForward,
                            BoundedDataFlowSlice.Direction.FORWARD, reported);
                    candidate.put("calleeFormalEvidence", finalEvidence);
                    candidate.put("boundaryStatus",
                        "decompiler_positional_candidate");
                    boolean candidateComplete = complete &&
                        coverage(intermediateArgEvidence) &&
                        coverage(finalEvidence);
                    candidate.put("complete", candidateComplete);
                }
                result.put("candidateSecondHops", candidates);
                result.put("secondHopCandidatesOmitted",
                    Math.max(0, forwarded.size() - candidates.size()));
                result.put("secondHopRejectedOrUnavailable", rejected);
                result.put("secondBoundaryStatus",
                    candidates.stream().anyMatch(c ->
                        "decompiler_positional_candidate".equals(
                            c.get("boundaryStatus")))
                        ? "candidate_list_available"
                        : "no_eligible_second_boundary");
                result.put("complete", !middleForward.truncated() &&
                    forwarded.size() == candidates.size() &&
                    rejected == 0 && !candidates.isEmpty() &&
                    candidates.stream().allMatch(c ->
                        Boolean.TRUE.equals(c.get("complete"))));
                return createJsonResult(result);
            }
            finally {
                decompiler.dispose();
            }
        });
    }

    private McpSchema.CallToolResult finish(
            Map<String, Object> result, String status) {
        result.put("firstBoundaryStatus", status);
        return createJsonResult(result);
    }

    private static boolean coverage(Map<String, Object> evidence) {
        return Boolean.TRUE.equals(evidence.get("complete"));
    }

    private static Map<String, Object> identity(Function function) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("name", function.getName());
        value.put("address", AddressUtil.formatAddress(function.getEntryPoint()));
        return value;
    }

    private static Map<String, Object> node(Varnode node) {
        Map<String, Object> value = new LinkedHashMap<>();
        value.put("address", AddressUtil.formatAddress(node.getAddress()));
        value.put("sizeBytes", node.getSize());
        if (node.getDef() != null) {
            value.put("definingOperation",
                node.getDef().getSeqnum().toString());
        }
        return value;
    }

    private static HighFunction decompile(
            DecompInterface decompiler, Function function) {
        DecompileResults results = decompiler.decompileFunction(function,
            DECOMPILE_TIMEOUT_SECONDS,
            TimeoutTaskMonitor.timeoutIn(
                DECOMPILE_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        return results != null && results.decompileCompleted()
            ? results.getHighFunction() : null;
    }

    // Null if not exactly one High P-code CALL/CALLIND at the machine site.
    private static PcodeOpAST uniqueCall(HighFunction high, Address site) {
        var ops = high.getPcodeOps(site);
        int scanned = 0;
        PcodeOpAST found = null;
        while (ops.hasNext()) {
            if (scanned++ >= 4096) {
                return null;
            }
            PcodeOpAST op = ops.next();
            if (op.getOpcode() == PcodeOp.CALL ||
                op.getOpcode() == PcodeOp.CALLIND) {
                if (found != null) {
                    return null;
                }
                found = op;
            }
        }
        return found;
    }

    private static Function directTarget(
            Program program, PcodeOp op) {
        if (op.getOpcode() != PcodeOp.CALL ||
            op.getNumInputs() == 0 || op.getInput(0) == null ||
            op.getInput(0).getAddress() == null) {
            return null;
        }
        return program.getFunctionManager().getFunctionAt(
            op.getInput(0).getAddress());
    }

    private static boolean eligibleStoredPrototype(
            Function function, int actualArgs, int selectedIndex) {
        if (actualArgs < 0 || actualArgs > MAX_CALL_ARGS ||
            selectedIndex < 0 || selectedIndex >= actualArgs ||
            function.isExternal() || function.isThunk() ||
            function.hasVarArgs() || function.hasCustomVariableStorage() ||
            function.hasUnknownCallingConventionName()) {
            return false;
        }
        Parameter[] formals = function.getParameters();
        if (formals.length != actualArgs) {
            return false;
        }
        for (Parameter formal : formals) {
            if (formal.isAutoParameter() || formal.isForcedIndirect()) {
                return false;
            }
        }
        return true;
    }

    private static List<Varnode> formalInstances(
            HighFunction high, Function stored, int index) {
        if (high.getFunctionPrototype() == null ||
            high.getFunctionPrototype().getNumParams() !=
                stored.getParameters().length) {
            return List.of();
        }
        HighSymbol symbol = high.getFunctionPrototype().getParam(index);
        if (symbol == null) {
            return List.of();
        }
        HighVariable formal = symbol.getHighVariable();
        if (!(formal instanceof HighParam parameter) ||
            parameter.getSlot() != index) {
            return List.of();
        }
        Varnode[] instances = formal.getInstances();
        if (instances == null || instances.length == 0 ||
            instances.length > MAX_SSA_SEEDS) {
            return List.of();
        }
        List<Varnode> seeds = new ArrayList<>();
        for (Varnode instance : instances) {
            if (instance != null) {
                seeds.add(instance);
            }
        }
        return seeds;
    }

    static record ForwardedArgument(PcodeOp call, int argumentIndex) {}

    /**
     * Conservative SSA-only propagation through explicitly supported
     * P-code value operations. No memory LOAD/STORE, CALL result,
     * indirect call, pointer alias, or interprocedural propagation.
     * Only P-code operations actually present in the bounded slice count.
     */
    static List<ForwardedArgument> observedForwardedArguments(
            List<Varnode> seeds, Set<PcodeOp> observed) {
        Set<Varnode> reached =
            Collections.newSetFromMap(new IdentityHashMap<Varnode, Boolean>());
        reached.addAll(seeds);
        List<PcodeOp> ordered = new ArrayList<>(observed);
        ordered.sort(Comparator.comparing(PcodeOp::getSeqnum));
        // Each pass must add a previously unseen output, so this is finite.
        for (int pass = 0; pass <= ordered.size(); pass++) {
            boolean changed = false;
            for (PcodeOp op : ordered) {
                if (!propagatesValue(op) || op.getOutput() == null) {
                    continue;
                }
                for (int i = 0; i < op.getNumInputs(); i++) {
                    if (reached.contains(op.getInput(i))) {
                        changed |= reached.add(op.getOutput());
                        break;
                    }
                }
            }
            if (!changed) {
                break;
            }
        }

        List<ForwardedArgument> found = new ArrayList<>();
        for (PcodeOp op : ordered) {
            if (op.getOpcode() != PcodeOp.CALL ||
                op.getNumInputs() < 2 ||
                op.getNumInputs() - 1 > MAX_CALL_ARGS) {
                continue;
            }
            for (int i = 1; i < op.getNumInputs(); i++) {
                if (reached.contains(op.getInput(i))) {
                    found.add(new ForwardedArgument(op, i - 1));
                }
            }
        }
        return found;
    }

    private static boolean propagatesValue(PcodeOp op) {
        return switch (op.getOpcode()) {
            case PcodeOp.COPY, PcodeOp.CAST,
                 PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT,
                 PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT,
                 PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR,
                 PcodeOp.PTRADD, PcodeOp.PTRSUB,
                 PcodeOp.PIECE, PcodeOp.SUBPIECE,
                 PcodeOp.MULTIEQUAL -> true;
            default -> false;
        };
    }
}
