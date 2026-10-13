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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
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
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * One-hop static evidence. There are TWO independent SSA graphs here, never
 * a synthetic caller-to-callee runtime edge or a recursively explored path.
 */
public final class OneHopValueFlowToolProvider extends AbstractToolProvider {
    private static final int DEFAULT_MAX_OPS = 128;
    private static final int HARD_MAX_OPS = 500;
    private static final int MAX_CALL_ARGS = 128;
    private static final int MAX_SERIALIZED_INPUTS_PER_OP = 32;
    private static final int MAX_MERGE_HOTSPOTS = 8;
    private static final int MAX_MERGE_INPUT_DEFS = 8;
    private static final int DECOMPILE_TIMEOUT_SECONDS = 30;
    private static final String SEMANTICS =
        "Separate caller backward and callee forward Ghidra High P-code " +
        "SSA slices. A positional correspondence is only a decompiler-derived " +
        "candidate, never a runtime-proven value equivalence, ABI storage " +
        "proof, alias resolution, or continuous interprocedural flow path.";

    public OneHopValueFlowToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath", SchemaUtil.stringProperty("Ghidra project path"));
        properties.put("callsite",
            SchemaUtil.stringProperty("Machine call instruction address or symbol"));
        properties.put("argumentIndex",
            SchemaUtil.integerPropertyWithDefault(
                "Selected zero-based High P-code CALL argument index", 0));
        properties.put("maxOperations",
            SchemaUtil.integerPropertyWithDefault(
                "Max P-code operations PER side, 1..500", DEFAULT_MAX_OPS));
        properties.put("maxReportedOperations",
            SchemaUtil.integerProperty(
                "Optional 0..maxOperations cap on operation records PER side. " +
                "Default returns all observed operations; lower values add a " +
                "bounded opcode/merge summary and explicitly mark serialized " +
                "coverage incomplete. Does not increase traversal limits."));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("trace-call-argument-one-hop")
            .title("Trace One Call Argument Across a Boundary")
            .description(
                "Read-only evidence for a single direct call argument. Returns " +
                "a bounded caller backward SSA slice and, when unambiguous, a " +
                "separate callee formal forward SSA slice. The inter-function " +
                "relationship is only a static decompiler candidate.")
            .inputSchema(createSchema(properties, List.of("programPath",
                "callsite", "argumentIndex")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address requested = getAddressFromArgs(request, program, "callsite");
            Instruction machineCall =
                program.getListing().getInstructionContaining(requested);
            if (machineCall == null || !machineCall.getFlowType().isCall()) {
                return createErrorResult("callsite is not a machine call");
            }
            Address callsite = machineCall.getAddress();
            Function caller = program.getFunctionManager()
                .getFunctionContaining(callsite);
            if (caller == null) {
                return createErrorResult("No caller function contains callsite");
            }
            int argIndex = getInt(request, "argumentIndex");
            int maxOps = getOptionalInt(request, "maxOperations", DEFAULT_MAX_OPS);
            if (argIndex < 0 || argIndex >= MAX_CALL_ARGS) {
                return createErrorResult("argumentIndex must be in [0,127]");
            }
            if (maxOps < 1 || maxOps > HARD_MAX_OPS) {
                return createErrorResult("maxOperations must be in [1,500]");
            }
            int maxReportedOps = getOptionalInt(
                request, "maxReportedOperations", maxOps);
            if (maxReportedOps < 0 || maxReportedOps > maxOps) {
                return createErrorResult(
                    "maxReportedOperations must be in [0,maxOperations]");
            }

            followRead(program, callsite);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("requestedAddress", AddressUtil.formatAddress(requested));
            result.put("callsite", AddressUtil.formatAddress(callsite));
            result.put("machineInstruction", machineCall.toString());
            result.put("caller", identity(caller));
            result.put("argumentIndex", argIndex);
            result.put("maxOperationsPerSide", maxOps);
            result.put("maxReportedOperationsPerSide", maxReportedOps);
            result.put("relationSemantics", SEMANTICS);
            result.put("callerEvidence", null);
            result.put("calleeEvidence", null);
            result.put("callee", null);
            result.put("complete", false);

            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(false);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(program)) {
                decompiler.dispose();
                return finish(result, "unavailable_decompiler", null);
            }
            try {
                HighFunction callerHigh = decompile(decompiler, caller);
                if (callerHigh == null) {
                    return finish(result, "unavailable_caller_decompilation", null);
                }

                List<PcodeOpAST> atSite = new ArrayList<>();
                var iterator = callerHigh.getPcodeOps(callsite);
                // Bounded number of operations at the address, to avoid
                // unbounded traversal if a corrupted decompiler model is used.
                int scanned = 0;
                while (iterator.hasNext()) {
                    if (scanned++ >= 4096) {
                        return finish(result, "unavailable_callsite_scan_budget", null);
                    }
                    PcodeOpAST op = iterator.next();
                    if (op.getOpcode() == PcodeOp.CALL ||
                        op.getOpcode() == PcodeOp.CALLIND) {
                        if (atSite.size() >= 2) {
                            return finish(result, "ambiguous_multiple_call_operations", null);
                        }
                        atSite.add(op);
                    }
                }
                if (atSite.size() != 1) {
                    return finish(result, atSite.isEmpty()
                        ? "unavailable_high_pcode_call"
                        : "ambiguous_multiple_call_operations", null);
                }

                PcodeOpAST call = atSite.get(0);
                result.put("callSequence", call.getSeqnum().toString());
                result.put("opcode", call.getMnemonic());
                int argCount = Math.max(0, call.getNumInputs() - 1);
                result.put("argumentCount", argCount);
                if (argCount > MAX_CALL_ARGS) {
                    return finish(result, "unavailable_argument_count_budget", null);
                }
                if (argIndex >= argCount) {
                    return finish(result, "unavailable_argument_index", null);
                }
                Varnode argument = call.getInput(argIndex + 1);
                if (argument == null) {
                    return finish(result, "unavailable_caller_argument", null);
                }
                result.put("callerArgument", describeNode(argument));
                BoundedDataFlowSlice.Result callerSlice = BoundedDataFlowSlice.collect(
                    List.of(argument), BoundedDataFlowSlice.Direction.BACKWARD, maxOps);
                Map<String, Object> callerEvidence =
                    sliceEvidence(caller, List.of(argument), callerSlice,
                        BoundedDataFlowSlice.Direction.BACKWARD, maxReportedOps);
                result.put("callerEvidence", callerEvidence);

                if (call.getOpcode() == PcodeOp.CALLIND) {
                    return finish(result, "unavailable_indirect_target", null);
                }
                if (call.getNumInputs() < 1 || call.getInput(0) == null ||
                    call.getInput(0).getAddress() == null) {
                    return finish(result, "unavailable_target", null);
                }

                Address targetAddress = call.getInput(0).getAddress();
                result.put("targetAddress", AddressUtil.formatAddress(targetAddress));
                Function callee =
                    program.getFunctionManager().getFunctionAt(targetAddress);
                if (callee == null) {
                    return finish(result, "unavailable_callee_function", null);
                }
                result.put("callee", identity(callee));
                if (callee.isExternal() || callee.isThunk()) {
                    return finish(result, "unavailable_external_or_thunk", null);
                }
                if (callee.getEntryPoint().equals(caller.getEntryPoint())) {
                    return finish(result, "unavailable_recursive_call", null);
                }

                Parameter[] formals = callee.getParameters();
                result.put("formalParameterCount", formals.length);
                result.put("calleeCallingConvention", callee.getCallingConventionName());
                result.put("calleeSignatureSource",
                    callee.getSignatureSource().toString());
                boolean variadic = callee.hasVarArgs();
                boolean customStorage = callee.hasCustomVariableStorage();
                boolean unknownConvention = callee.hasUnknownCallingConventionName();
                result.put("calleeVariadic", variadic);
                result.put("calleeCustomStorage", customStorage);
                result.put("calleeUnknownCallingConvention", unknownConvention);
                if (formals.length > MAX_CALL_ARGS) {
                    return finish(result, "unavailable_formal_count_budget", null);
                }
                List<String> ambiguities = new ArrayList<>();
                if (variadic) {
                    ambiguities.add("variadic");
                }
                if (customStorage) {
                    ambiguities.add("custom_parameter_storage");
                }
                if (unknownConvention) {
                    ambiguities.add("unknown_calling_convention");
                }
                for (Parameter formal : formals) {
                    if (formal.isAutoParameter() &&
                        !ambiguities.contains("auto_parameter")) {
                        ambiguities.add("auto_parameter");
                    }
                    if (formal.isForcedIndirect() &&
                        !ambiguities.contains("forced_indirect_parameter")) {
                        ambiguities.add("forced_indirect_parameter");
                    }
                }
                result.put("prototypeAmbiguities", ambiguities);
                if (!ambiguities.isEmpty()) {
                    return finish(result, "ambiguous_prototype_or_storage", null);
                }
                if (argCount != formals.length || argIndex >= formals.length) {
                    return finish(result, "ambiguous_parameter_count", null);
                }

                HighFunction calleeHigh = decompile(decompiler, callee);
                if (calleeHigh == null) {
                    return finish(result, "unavailable_callee_decompilation", null);
                }
                if (calleeHigh.getFunctionPrototype() == null) {
                    return finish(result, "unavailable_decompiler_prototype", null);
                }
                int inferredParams = calleeHigh.getFunctionPrototype().getNumParams();
                result.put("decompilerParameterCount", inferredParams);
                if (inferredParams != formals.length) {
                    return finish(result, "ambiguous_decompiler_parameter_count", null);
                }
                HighSymbol formalSymbol =
                    calleeHigh.getFunctionPrototype().getParam(argIndex);
                if (formalSymbol == null) {
                    return finish(result, "unavailable_decompiler_formal_symbol", null);
                }
                HighVariable formalHigh = formalSymbol.getHighVariable();
                if (!(formalHigh instanceof HighParam param) ||
                    param.getSlot() != argIndex) {
                    return finish(result, "ambiguous_decompiler_formal_identity", null);
                }
                Varnode[] instances = formalHigh.getInstances();
                if (instances == null || instances.length == 0) {
                    return finish(result, "unavailable_formal_ssa_instances", null);
                }
                if (instances.length > 128) {
                    return finish(result, "unavailable_formal_instance_budget", null);
                }
                List<Varnode> seeds = new ArrayList<>();
                for (Varnode node : instances) {
                    if (node != null) {
                        seeds.add(node);
                    }
                }
                if (seeds.isEmpty()) {
                    return finish(result, "unavailable_formal_ssa_instances", null);
                }
                // This is intentionally a *second* graph: there is no
                // synthetic edge from 'argument' to any callee instance.
                BoundedDataFlowSlice.Result calleeSlice = BoundedDataFlowSlice.collect(
                    seeds, BoundedDataFlowSlice.Direction.FORWARD, maxOps);
                Map<String, Object> formalEvidence = new LinkedHashMap<>();
                formalEvidence.put("index", argIndex);
                formalEvidence.put("name", formalSymbol.getName());
                formalEvidence.put("slot", param.getSlot());
                formalEvidence.put("type", formals[argIndex].getDataType().getDisplayName());
                formalEvidence.put("storage",
                    formals[argIndex].getVariableStorage().toString());
                formalEvidence.put("ssaInstanceCount", seeds.size());
                result.put("calleeFormal", formalEvidence);
                Map<String, Object> calleeEvidence =
                    sliceEvidence(callee, seeds, calleeSlice,
                        BoundedDataFlowSlice.Direction.FORWARD, maxReportedOps);
                List<Map<String, Object>> seedNodes = new ArrayList<>();
                for (Varnode node : seeds) {
                    seedNodes.add(describeNode(node));
                }
                calleeEvidence.put("ssaSeeds", seedNodes);
                result.put("calleeEvidence", calleeEvidence);

                // Even serialization truncation must prevent a top-level
                // claim that the two evidence graphs are complete.
                return finish(result, "decompiler_positional_candidate",
                    completeEvidence(callerEvidence, calleeEvidence));
            }
            finally {
                decompiler.dispose();
            }
        });
    }

    /**
     * Completion is an AND of independently serialized evidence graphs;
     * a candidate relation does not override either side's truncation.
     * Package scope allows regression tests with deliberately oversized
     * synthetic SSA graphs, without relying on compiler optimizations.
     */
    static boolean completeEvidence(Map<String, Object> caller,
            Map<String, Object> callee) {
        return caller != null && callee != null &&
            Boolean.TRUE.equals(caller.get("complete")) &&
            Boolean.TRUE.equals(callee.get("complete"));
    }

    private McpSchema.CallToolResult finish(
            Map<String, Object> result, String status, Boolean complete) {
        result.put("relationStatus", status);
        result.put("complete", Boolean.TRUE.equals(complete));
        return createJsonResult(result);
    }

    private static HighFunction decompile(
            DecompInterface d, Function function) {
        DecompileResults result = d.decompileFunction(function,
            DECOMPILE_TIMEOUT_SECONDS, TimeoutTaskMonitor.timeoutIn(
                DECOMPILE_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        return result != null && result.decompileCompleted()
            ? result.getHighFunction() : null;
    }

    private static Map<String, Object> identity(Function f) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("name", f.getName());
        item.put("address", AddressUtil.formatAddress(f.getEntryPoint()));
        item.put("external", f.isExternal());
        item.put("thunk", f.isThunk());
        return item;
    }

    private static Map<String, Object> describeNode(Varnode node) {
        Map<String, Object> item = new LinkedHashMap<>();
        item.put("address", AddressUtil.formatAddress(node.getAddress()));
        item.put("sizeBytes", node.getSize());
        item.put("constant", node.isConstant());
        item.put("register", node.isRegister());
        item.put("unique", node.isUnique());
        if (node instanceof VarnodeAST ast) {
            item.put("ssaUniqueId", ast.getUniqueId());
        }
        if (node.getDef() != null && node.getDef().getSeqnum() != null) {
            item.put("definingOperation", node.getDef().getSeqnum().toString());
        }
        if (node.getHigh() != null && node.getHigh().getName() != null) {
            item.put("highVariableName", node.getHigh().getName());
        }
        if (node.isConstant()) {
            item.put("constantUnsignedHex",
                Long.toUnsignedString(node.getOffset(), 16));
        }
        return item;
    }


    /**
     * A compact index over the operations actually observed by the bounded
     * slice, never a statement about unexplored predecessors or successors.
     * Rank high-fan-in MULTIEQUAL merge points deterministically so an analyst
     * can request more evidence at their exact P-code sequence/address.
     */
    static Map<String, Object> operationSummary(
            BoundedDataFlowSlice.Result slice) {
        Map<String, Integer> counts = new TreeMap<>();
        List<PcodeOp> merges = new ArrayList<>();
        for (PcodeOp op : slice.operations()) {
            counts.merge(op.getMnemonic(), 1, Integer::sum);
            if (op.getOpcode() == PcodeOp.MULTIEQUAL) {
                merges.add(op);
            }
        }
        merges.sort(Comparator.comparingInt(PcodeOp::getNumInputs)
            .reversed().thenComparing(PcodeOp::getSeqnum));

        List<Map<String, Object>> hotspots = new ArrayList<>();
        for (int i = 0; i < Math.min(merges.size(), MAX_MERGE_HOTSPOTS); i++) {
            PcodeOp op = merges.get(i);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("sequence", op.getSeqnum().toString());
            item.put("address",
                AddressUtil.formatAddress(op.getSeqnum().getTarget()));
            item.put("inputCount", op.getNumInputs());
            item.put("output", op.getOutput() == null
                ? null : describeNode(op.getOutput()));
            List<Map<String, Object>> inputDefinitions = new ArrayList<>();
            for (int j = 0; j < Math.min(op.getNumInputs(),
                    MAX_MERGE_INPUT_DEFS); j++) {
                Varnode node = op.getInput(j);
                PcodeOp def = node == null ? null : node.getDef();
                Map<String, Object> input = new LinkedHashMap<>();
                input.put("index", j);
                input.put("definingOperation", def == null
                    ? null : def.getSeqnum().toString());
                inputDefinitions.add(input);
            }
            item.put("inputDefinitions", inputDefinitions);
            item.put("inputDefinitionsOmitted",
                op.getNumInputs() - inputDefinitions.size());
            hotspots.add(item);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("scope", "observed_slice_operations_only");
        result.put("traversalTruncated", slice.truncated());
        result.put("observedOperationCount", slice.operations().size());
        result.put("observedOpcodeCounts", counts);
        result.put("observedMergeCount", merges.size());
        result.put("mergeHotspots", hotspots);
        result.put("mergeHotspotsOmitted", merges.size() - hotspots.size());
        return result;
    }


    /**
     * Select only operations already observed by the bounded SSA traversal.
     * When a compact cap applies, prioritize the seed's closest producers
     * (backward) or consumers (forward), breadth-first. Sorting each distance
     * layer by P-code sequence makes the result independent of def/use
     * iteration order. Remaining slots use the original sequence order.
     *
     * This is OUTPUT selection, not additional dataflow exploration. Never
     * follow a definition outside slice.operations(), or across CALLs.
     */
    static List<PcodeOp> selectReportedOperations(
            BoundedDataFlowSlice.Result slice, List<Varnode> seeds,
            BoundedDataFlowSlice.Direction direction, int limit) {
        List<PcodeOp> observedOrder = new ArrayList<>(slice.operations());
        if (limit >= observedOrder.size()) {
            return observedOrder; // Frozen full-operation response ordering.
        }
        List<PcodeOp> selected = new ArrayList<>();
        if (limit == 0) {
            return selected;
        }

        Set<PcodeOp> observed =
            Collections.newSetFromMap(new IdentityHashMap<PcodeOp, Boolean>());
        observed.addAll(observedOrder);
        Set<PcodeOp> chosen =
            Collections.newSetFromMap(new IdentityHashMap<PcodeOp, Boolean>());
        Set<Varnode> visited =
            Collections.newSetFromMap(new IdentityHashMap<Varnode, Boolean>());

        // The forward index is built ONLY from the bounded observed set.
        // Limit operand inspection to match the existing 32-input output cap.
        Map<Varnode, List<PcodeOp>> consumers = new IdentityHashMap<>();
        if (direction == BoundedDataFlowSlice.Direction.FORWARD) {
            for (PcodeOp op : observedOrder) {
                for (int i = 0; i < Math.min(op.getNumInputs(),
                        MAX_SERIALIZED_INPUTS_PER_OP); i++) {
                    Varnode node = op.getInput(i);
                    if (node != null) {
                        consumers.computeIfAbsent(node,
                            ignored -> new ArrayList<>()).add(op);
                    }
                }
            }
        }

        List<Varnode> frontier = new ArrayList<>(seeds);
        while (!frontier.isEmpty() && selected.size() < limit) {
            List<PcodeOp> level = new ArrayList<>();
            for (Varnode node : frontier) {
                if (node == null || !visited.add(node)) {
                    continue;
                }
                if (direction == BoundedDataFlowSlice.Direction.BACKWARD) {
                    PcodeOp def = node.getDef();
                    if (def != null && observed.contains(def) &&
                        !chosen.contains(def)) {
                        level.add(def);
                    }
                }
                else {
                    for (PcodeOp use : consumers.getOrDefault(node, List.of())) {
                        if (!chosen.contains(use)) {
                            level.add(use);
                        }
                    }
                }
            }
            level.sort(Comparator.comparing(PcodeOp::getSeqnum));
            List<Varnode> next = new ArrayList<>();
            for (PcodeOp op : level) {
                if (!chosen.add(op)) {
                    continue;
                }
                selected.add(op);
                if (selected.size() >= limit) {
                    break;
                }
                // A call result/argument is an analysis boundary, not a
                // gateway into callee SSA or other side effects.
                if (op.getOpcode() == PcodeOp.CALL ||
                    op.getOpcode() == PcodeOp.CALLIND) {
                    continue;
                }
                if (direction == BoundedDataFlowSlice.Direction.BACKWARD) {
                    for (int i = 0; i < Math.min(op.getNumInputs(),
                            MAX_SERIALIZED_INPUTS_PER_OP); i++) {
                        Varnode input = op.getInput(i);
                        if (input != null) {
                            next.add(input);
                        }
                    }
                }
                else if (op.getOutput() != null) {
                    next.add(op.getOutput());
                }
            }
            frontier = next;
        }
        for (PcodeOp op : observedOrder) {
            if (selected.size() >= limit) {
                break;
            }
            if (chosen.add(op)) {
                selected.add(op);
            }
        }
        return selected;
    }

    static Map<String, Object> sliceEvidence(
            Function function, Varnode seed,
            BoundedDataFlowSlice.Result slice) {
        // Preserve the frozen Slice 5B result contract for existing callers.
        return sliceEvidence(function, List.of(seed), slice,
            BoundedDataFlowSlice.Direction.BACKWARD, HARD_MAX_OPS);
    }

    static Map<String, Object> sliceEvidence(
            Function function, Varnode seed,
            BoundedDataFlowSlice.Result slice, int maxReportedOperations) {
        return sliceEvidence(function, List.of(seed), slice,
            BoundedDataFlowSlice.Direction.BACKWARD, maxReportedOperations);
    }

    static Map<String, Object> sliceEvidence(
            Function function, List<Varnode> seeds,
            BoundedDataFlowSlice.Result slice,
            BoundedDataFlowSlice.Direction direction,
            int maxReportedOperations) {
        if (maxReportedOperations < 0 ||
            maxReportedOperations > HARD_MAX_OPS) {
            throw new IllegalArgumentException(
                "maxReportedOperations must be in [0,500]");
        }
        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("function", identity(function));
        evidence.put("seed", describeNode(seeds.get(0)));
        // Completion is finalized after output serialization, because
        // large P-code operands may have to be capped independently.
        evidence.put("complete", !slice.truncated());
        evidence.put("truncated", slice.truncated());
        evidence.put("truncationReason", slice.truncationReason());
        evidence.put("visitedVarnodes", slice.visitedVarnodes());
        evidence.put("scannedEdges", slice.scannedEdges());
        evidence.put("operationCount", slice.operations().size());
        evidence.put("operationSummary", operationSummary(slice));
        evidence.put("operationSelection", maxReportedOperations <
            slice.operations().size()
            ? "seed_proximity_within_observed_slice"
            : "full_observed_sequence_order");
        List<Map<String, Object>> operations = new ArrayList<>();
        boolean operandsTruncated = false;
        for (PcodeOp op : selectReportedOperations(
                slice, seeds, direction, maxReportedOperations)) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("sequence", op.getSeqnum().toString());
            item.put("address",
                AddressUtil.formatAddress(op.getSeqnum().getTarget()));
            item.put("opcode", op.getMnemonic());
            item.put("inputCount", op.getNumInputs());
            item.put("inputsTruncated",
                op.getNumInputs() > MAX_SERIALIZED_INPUTS_PER_OP);
            operandsTruncated |= op.getNumInputs() > MAX_SERIALIZED_INPUTS_PER_OP;
            List<Map<String, Object>> inputs = new ArrayList<>();
            for (int i = 0; i < Math.min(op.getNumInputs(),
                    MAX_SERIALIZED_INPUTS_PER_OP); i++) {
                Varnode input = op.getInput(i);
                inputs.add(input == null ? null : describeNode(input));
            }
            item.put("inputs", inputs);
            Varnode output = op.getOutput();
            item.put("output", output == null ? null : describeNode(output));
            operations.add(item);
        }
        evidence.put("operations", operations);
        evidence.put("reportedOperationCount", operations.size());
        int operationsOmitted = slice.operations().size() - operations.size();
        evidence.put("operationsOmitted", operationsOmitted);
        evidence.put("serializationLimited", operationsOmitted > 0 ||
            operandsTruncated);
        evidence.put("operandsTruncated", operandsTruncated);
        if (operationsOmitted > 0) {
            evidence.put("complete", false);
            evidence.put("truncated", true);
            if (!slice.truncated()) {
                evidence.put("truncationReason", "serialized_operation_budget");
            }
        }
        if (operandsTruncated) {
            evidence.put("complete", false);
            evidence.put("truncated", true);
            if (!slice.truncated()) {
                evidence.put("truncationReason", "serialized_input_budget");
            }
        }
        return evidence;
    }
}
