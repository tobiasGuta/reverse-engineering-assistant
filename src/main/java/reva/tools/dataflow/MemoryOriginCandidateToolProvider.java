/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package reva.tools.dataflow;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
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
 * A deliberately limited memory-ORIGIN HYPOTHESIS tool.
 *
 * It reports intraprocedural STOREs with the same memory-space selector and
 * a syntactically equivalent SSA pointer + constant offset as a selected
 * decompiler LOAD. It DOES NOT prove that any store reaches the load.
 * Missing stores are not proof of no alias; phi nodes, pointer aliasing,
 * intervening writes, path feasibility and CALL side effects are unresolved.
 */
public final class MemoryOriginCandidateToolProvider extends AbstractToolProvider {
    private static final int DEFAULT_SCAN = 4096;
    private static final int MAX_SCAN = 10000;
    private static final int DEFAULT_SLICE = 128;
    private static final int MAX_SLICE = 500;
    private static final int DEFAULT_REPORTED = 12;
    private static final int MAX_CANDIDATES = 8;
    private static final int MAX_SITE_OPS = 1024;
    private static final int MAX_POINTER_DEPTH = 16;
    private static final int DECOMPILE_SECONDS = 30;
    private static final String SEMANTICS =
        "Intraprocedural syntactic STORE candidates for a High P-code LOAD. " +
        "A matching SSA pointer expression is NOT a reaching definition, " +
        "memory-value equivalence, alias proof, feasible path, or runtime origin. " +
        "Unmatched pointers may alias; CALLs and unknown writes may intervene.";

    public MemoryOriginCandidateToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        Map<String, Object> props = new LinkedHashMap<>();
        props.put("programPath", SchemaUtil.stringProperty("Ghidra project path"));
        props.put("loadAddress", SchemaUtil.stringProperty(
            "Machine instruction address containing a High P-code LOAD"));
        props.put("maxScannedOperations", SchemaUtil.integerPropertyWithDefault(
            "Cap on High P-code operations inspected in this function (1..10000)",
            DEFAULT_SCAN));
        props.put("maxSliceOperations", SchemaUtil.integerPropertyWithDefault(
            "Max backward SSA operations per candidate stored value (1..500)",
            DEFAULT_SLICE));
        props.put("maxReportedOperations", SchemaUtil.integerPropertyWithDefault(
            "Max detailed SSA operations per candidate (0..maxSliceOperations)",
            DEFAULT_REPORTED));
        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("trace-memory-load-origins")
            .title("Find Bounded Candidate Stores For A Memory Load")
            .description("Read-only, conservative intraprocedural address-expression " +
                "matches. Does not prove aliasing or memory reaching definitions.")
            .inputSchema(createSchema(props, List.of("programPath", "loadAddress")))
            .build();
        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address requested = getAddressFromArgs(request, program, "loadAddress");
            int scanBudget = getOptionalInt(request, "maxScannedOperations", DEFAULT_SCAN);
            int sliceBudget = getOptionalInt(request, "maxSliceOperations", DEFAULT_SLICE);
            int reported = getOptionalInt(request, "maxReportedOperations",
                Math.min(DEFAULT_REPORTED, sliceBudget));
            if (scanBudget < 1 || scanBudget > MAX_SCAN ||
                sliceBudget < 1 || sliceBudget > MAX_SLICE ||
                reported < 0 || reported > sliceBudget) {
                return createErrorResult("Invalid scan (1..10000), slice (1..500) " +
                    "or reported (0..maxSliceOperations) budget");
            }
            Instruction machine =
                program.getListing().getInstructionContaining(requested);
            if (machine == null) {
                return createErrorResult("No machine instruction at loadAddress");
            }
            Address site = machine.getAddress();
            Function function = program.getFunctionManager()
                .getFunctionContaining(site);
            if (function == null) {
                return createErrorResult("No function contains loadAddress");
            }
            followRead(program, site);
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("function", function.getName());
            result.put("functionAddress",
                AddressUtil.formatAddress(function.getEntryPoint()));
            result.put("loadAddress", AddressUtil.formatAddress(site));
            result.put("machineInstruction", machine.toString());
            result.put("semantics", SEMANTICS);
            result.put("candidateStores", List.of());
            result.put("maxScannedOperations", scanBudget);
            result.put("maxSliceOperations", sliceBudget);
            result.put("maxReportedOperations", reported);
            result.put("maxCandidateStoreRecords", MAX_CANDIDATES);
            result.put("provenReachingDefinitions", 0);
            result.put("memoryOriginResolved", false);
            result.put("enumerationComplete", false);
            result.put("status", "unavailable");

            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(false);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(program)) {
                decompiler.dispose();
                return finish(result, "unavailable_decompiler");
            }
            try {
                DecompileResults d = decompiler.decompileFunction(function,
                    DECOMPILE_SECONDS, TimeoutTaskMonitor.timeoutIn(
                        DECOMPILE_SECONDS, TimeUnit.SECONDS));
                HighFunction high = d != null && d.decompileCompleted()
                    ? d.getHighFunction() : null;
                if (high == null) {
                    return finish(result, "unavailable_decompilation");
                }

                var siteOps = high.getPcodeOps(site);
                PcodeOpAST load = null;
                int atSite = 0;
                while (siteOps.hasNext()) {
                    if (++atSite > MAX_SITE_OPS) {
                        return finish(result, "unavailable_load_site_scan_budget");
                    }
                    PcodeOpAST op = siteOps.next();
                    if (op.getOpcode() == PcodeOp.LOAD) {
                        if (load != null) {
                            return finish(result, "ambiguous_multiple_high_loads");
                        }
                        load = op;
                    }
                }
                if (load == null || load.getNumInputs() < 2 ||
                    load.getInput(0) == null || load.getInput(1) == null ||
                    load.getOutput() == null) {
                    return finish(result, "unavailable_high_pcode_load");
                }
                result.put("loadSequence", load.getSeqnum().toString());
                result.put("loadSpaceId", load.getInput(0).getOffset());
                result.put("loadWidthBytes", load.getOutput().getSize());
                result.put("loadPointer",
                    AddressUtil.formatAddress(load.getInput(1).getAddress()));
                PointerKey loadPointer = pointerKey(load.getInput(1));
                result.put("loadPointerNormalization", loadPointer.kind);

                List<PcodeOpAST> found = new ArrayList<>();
                int eligibleStores = 0;
                int potentialCalls = 0;
                int scanned = 0;
                boolean scanTruncated = false;
                var allOps = high.getPcodeOps();
                while (allOps.hasNext()) {
                    if (scanned >= scanBudget) {
                        scanTruncated = true;
                        break;
                    }
                    PcodeOpAST op = allOps.next();
                    scanned++;
                    if (op.getOpcode() == PcodeOp.CALL ||
                        op.getOpcode() == PcodeOp.CALLIND) {
                        potentialCalls++;
                    }
                    if (op.getOpcode() != PcodeOp.STORE ||
                        op.getNumInputs() < 3 || op.getInput(0) == null ||
                        op.getInput(1) == null || op.getInput(2) == null) {
                        continue;
                    }
                    if (op.getInput(0).getOffset() != load.getInput(0).getOffset()) {
                        continue;
                    }
                    PointerKey storePointer = pointerKey(op.getInput(1));
                    if (!samePointerTerm(loadPointer, storePointer)) {
                        continue;
                    }
                    eligibleStores++;
                    if (found.size() < MAX_CANDIDATES) {
                        found.add(op);
                    }
                }
                found.sort(Comparator.comparing(PcodeOp::getSeqnum));
                List<Map<String, Object>> candidates = new ArrayList<>();
                boolean sliceTruncated = false;
                for (PcodeOpAST op : found) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("storeAddress",
                        AddressUtil.formatAddress(op.getSeqnum().getTarget()));
                    item.put("storeSequence", op.getSeqnum().toString());
                    item.put("memorySpaceId", op.getInput(0).getOffset());
                    item.put("storedWidthBytes", op.getInput(2).getSize());
                    item.put("loadedWidthBytes", load.getOutput().getSize());
                    item.put("addressRelation", "same_ssa_base_and_constant_offset");
                    item.put("reachingDefinition", "unproven");
                    item.put("storePointer",
                        AddressUtil.formatAddress(op.getInput(1).getAddress()));
                    BoundedDataFlowSlice.Result slice =
                        BoundedDataFlowSlice.collect(List.of(op.getInput(2)),
                            BoundedDataFlowSlice.Direction.BACKWARD, sliceBudget);
                    sliceTruncated |= slice.truncated();
                    item.put("storedValueEvidence",
                        OneHopValueFlowToolProvider.sliceEvidence(
                            function, List.of(op.getInput(2)), slice,
                            BoundedDataFlowSlice.Direction.BACKWARD, reported));
                    candidates.add(item);
                }
                result.put("candidateStores", candidates);
                result.put("matchingStoresObserved", eligibleStores);
                result.put("candidateStoresOmitted",
                    eligibleStores - candidates.size());
                result.put("scannedOperations", scanned);
                result.put("scanTruncated", scanTruncated);
                result.put("valueSliceTruncated", sliceTruncated);
                result.put("observedCallSideEffects", potentialCalls);
                result.put("enumerationComplete",
                    !scanTruncated && eligibleStores <= MAX_CANDIDATES);
                result.put("status", scanTruncated
                    ? "incomplete_scan_budget"
                    : eligibleStores > 0
                        ? "syntactic_store_candidates_only"
                        : "unresolved_no_syntactic_store");
                return createJsonResult(result);
            }
            finally {
                decompiler.dispose();
            }
        });
    }

    private McpSchema.CallToolResult finish(
            Map<String, Object> result, String status) {
        result.put("status", status);
        return createJsonResult(result);
    }

    /** Same SSA base and same constant offset, never a general alias claim. */
    static boolean samePointerTerm(PointerKey a, PointerKey b) {
        return a != null && b != null && a.root == b.root &&
            a.offset == b.offset;
    }

    static record PointerKey(Varnode root, long offset, String kind) {}

    private static PointerKey pointerKey(Varnode node) {
        Set<Varnode> visited =
            java.util.Collections.newSetFromMap(
                new IdentityHashMap<Varnode, Boolean>());
        return pointerKey(node, 0L, 0, visited);
    }

    private static PointerKey pointerKey(
            Varnode node, long offset, int depth, Set<Varnode> visited) {
        if (node == null) {
            return null;
        }
        if (depth >= MAX_POINTER_DEPTH || !visited.add(node)) {
            // Preserve identity of the exact term but do not assume aliases.
            return new PointerKey(node, offset, "unexpanded_budget_or_cycle");
        }
        if (node.isConstant()) {
            try {
                return new PointerKey(null,
                    Math.addExact(offset, signedConstant(node)),
                    "absolute_constant");
            }
            catch (ArithmeticException ex) {
                return new PointerKey(node, offset, "unexpanded_overflow");
            }
        }
        PcodeOp def = node.getDef();
        if (def == null) {
            return new PointerKey(node, offset, "ssa_leaf");
        }
        int op = def.getOpcode();
        if ((op == PcodeOp.COPY || op == PcodeOp.CAST) &&
            def.getNumInputs() == 1 && def.getInput(0) != null &&
            def.getInput(0).getSize() == node.getSize()) {
            return pointerKey(def.getInput(0), offset, depth + 1, visited);
        }
        Varnode base = null;
        Long displacement = null;
        if ((op == PcodeOp.INT_ADD || op == PcodeOp.PTRSUB) &&
            def.getNumInputs() == 2) {
            Varnode x = def.getInput(0);
            Varnode y = def.getInput(1);
            if (x != null && y != null) {
                if (y.isConstant() && !x.isConstant()) {
                    base = x;
                    displacement = signedConstant(y);
                }
                else if (op == PcodeOp.INT_ADD &&
                        x.isConstant() && !y.isConstant()) {
                    base = y;
                    displacement = signedConstant(x);
                }
            }
        }
        if (op == PcodeOp.PTRADD && def.getNumInputs() == 3) {
            Varnode x = def.getInput(0);
            Varnode y = def.getInput(1);
            Varnode z = def.getInput(2);
            if (x != null && y != null && z != null &&
                y.isConstant() && z.isConstant()) {
                try {
                    base = x;
                    displacement = Math.multiplyExact(
                        signedConstant(y), signedConstant(z));
                }
                catch (ArithmeticException ex) {
                    base = null;
                }
            }
        }
        if (base != null && displacement != null) {
            try {
                return pointerKey(base, Math.addExact(offset, displacement),
                    depth + 1, visited);
            }
            catch (ArithmeticException ex) {
                return new PointerKey(node, offset, "unexpanded_overflow");
            }
        }
        return new PointerKey(node, offset, "ssa_opaque_term");
    }

    private static long signedConstant(Varnode constant) {
        int bits = constant.getSize() * 8;
        long raw = constant.getOffset();
        if (bits > 0 && bits < 64) {
            int shift = 64 - bits;
            return (raw << shift) >> shift;
        }
        return raw;
    }
}
