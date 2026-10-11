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

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

/**
 * Deterministic, budget-aware intraprocedural SSA slice.
 *
 * <p>Equivalent direction and CALL/CALLIND boundaries to Ghidra 12.1.3's
 * DecompilerUtils slice helpers, but does not materialize an unbounded slice
 * before applying ReVa's operation limit. This is not memory-alias analysis,
 * cross-function tracing, or an execution trace.</p>
 */
final class BoundedDataFlowSlice {
    static final int DEFAULT_MAX_OPS = 500;
    static final int MAX_VISITED_VARNODES = 10000;
    static final int MAX_PENDING_VARNODES = 10000;
    static final int MAX_DESCENDANTS_PER_VARNODE = 10000;
    static final int MAX_INPUTS_PER_OPERATION = 10000;

    enum Direction { BACKWARD, FORWARD }

    record Result(Set<PcodeOp> operations, boolean truncated,
                  String truncationReason, int visitedVarnodes) {}

    private static final Comparator<PcodeOp> OP_ORDER =
        Comparator.comparing(PcodeOp::getSeqnum);

    private static final Comparator<Varnode> VARNODE_ORDER =
        Comparator.comparing(Varnode::getAddress)
            .thenComparingInt(Varnode::getSize)
            .thenComparingInt(v -> v instanceof ghidra.program.model.pcode.VarnodeAST ast
                ? ast.getUniqueId() : 0)
            .thenComparing(v -> v.getDef() != null
                ? v.getDef().getSeqnum().toString() : "");

    private BoundedDataFlowSlice() {}

    static Result collect(List<Varnode> seeds, Direction direction, int operationLimit) {
        if (operationLimit <= 0) {
            throw new IllegalArgumentException("operationLimit must be positive");
        }
        Set<PcodeOp> included =
            Collections.newSetFromMap(new IdentityHashMap<PcodeOp, Boolean>());
        Set<Varnode> visited =
            Collections.newSetFromMap(new IdentityHashMap<Varnode, Boolean>());
        Set<Varnode> scheduled =
            Collections.newSetFromMap(new IdentityHashMap<Varnode, Boolean>());
        ArrayDeque<Varnode> queue = new ArrayDeque<>();
        int processed = 0;
        String reason = null;

        List<Varnode> orderedSeeds = new ArrayList<>();
        for (Varnode seed : seeds) {
            if (seed != null) {
                orderedSeeds.add(seed);
            }
        }
        orderedSeeds.sort(VARNODE_ORDER);
        for (Varnode seed : orderedSeeds) {
            if (scheduled.add(seed)) {
                if (queue.size() >= MAX_PENDING_VARNODES) {
                    reason = "pending_varnode_budget";
                    break;
                }
                queue.addLast(seed);
            }
        }

        while (reason == null && !queue.isEmpty()) {
            if (processed >= MAX_VISITED_VARNODES) {
                reason = "visited_varnode_budget";
                break;
            }
            Varnode node = queue.removeFirst();
            if (!visited.add(node)) {
                continue;
            }
            processed++;

            if (direction == Direction.BACKWARD) {
                PcodeOp op = node.getDef();
                if (op == null) {
                    continue;
                }
                if (!included.contains(op) && included.size() >= operationLimit) {
                    reason = "operation_budget";
                    break;
                }
                included.add(op);
                if (isCall(op)) {
                    continue;
                }
                if (op.getNumInputs() > MAX_INPUTS_PER_OPERATION) {
                    reason = "input_fanout_budget";
                    break;
                }
                List<Varnode> inputs = new ArrayList<>();
                for (int i = 0; i < op.getNumInputs(); i++) {
                    Varnode input = op.getInput(i);
                    if (input != null) {
                        inputs.add(input);
                    }
                }
                inputs.sort(VARNODE_ORDER);
                for (Varnode input : inputs) {
                    if (scheduled.add(input)) {
                        if (queue.size() >= MAX_PENDING_VARNODES) {
                            reason = "pending_varnode_budget";
                            break;
                        }
                        queue.addLast(input);
                    }
                }
            }
            else {
                List<PcodeOp> descendants = new ArrayList<>();
                Iterator<PcodeOp> uses = node.getDescendants();
                while (uses.hasNext()) {
                    if (descendants.size() >= MAX_DESCENDANTS_PER_VARNODE) {
                        reason = "descendant_fanout_budget";
                        break;
                    }
                    PcodeOp op = uses.next();
                    if (op != null) {
                        descendants.add(op);
                    }
                }
                if (reason != null) {
                    break; // No partially ordered fan-out is incorporated.
                }
                descendants.sort(OP_ORDER);
                for (PcodeOp op : descendants) {
                    if (!included.contains(op) && included.size() >= operationLimit) {
                        reason = "operation_budget";
                        break;
                    }
                    included.add(op);
                    Varnode output = op.getOutput();
                    if (output != null && !isCall(op) && scheduled.add(output)) {
                        if (queue.size() >= MAX_PENDING_VARNODES) {
                            reason = "pending_varnode_budget";
                            break;
                        }
                        queue.addLast(output);
                    }
                }
            }
        }

        List<PcodeOp> ordered = new ArrayList<>(included);
        ordered.sort(OP_ORDER);
        return new Result(Collections.unmodifiableSet(new LinkedHashSet<>(ordered)),
            reason != null, reason, processed);
    }

    private static boolean isCall(PcodeOp op) {
        return op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND;
    }
}
