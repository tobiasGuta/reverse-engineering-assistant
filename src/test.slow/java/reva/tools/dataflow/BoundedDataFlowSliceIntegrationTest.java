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

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

import org.junit.Test;

import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import reva.RevaIntegrationTestBase;

/**
 * Synthetic SSA def/use graphs avoid external binary and Git LFS requirements.
 * These tests exercise operation boundaries, traversal order and CALL cutoffs
 * with genuine Ghidra VarnodeAST relationships.
 */
public class BoundedDataFlowSliceIntegrationTest
        extends RevaIntegrationTestBase {

    private record Chain(VarnodeAST[] nodes, PcodeOp[] operations) {}

    private Address addr(long offset) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    private Chain chain(int opCount) {
        VarnodeAST[] nodes = new VarnodeAST[opCount + 1];
        for (int i = 0; i < nodes.length; i++) {
            nodes[i] = new VarnodeAST(addr(0x01002000L + i * 8L), 4, i);
        }
        PcodeOp[] operations = new PcodeOp[opCount];
        for (int i = 0; i < opCount; i++) {
            PcodeOp op = new PcodeOp(
                addr(0x01000300L + i), i, PcodeOp.COPY,
                new Varnode[] {nodes[i]}, nodes[i + 1]);
            nodes[i + 1].setDef(op);
            nodes[i].addDescendant(op);
            operations[i] = op;
        }
        return new Chain(nodes, operations);
    }

    @Test
    public void testExactlyAtOperationBudgetIsComplete() {
        Chain graph = chain(500);
        var forward = BoundedDataFlowSlice.collect(
            List.of(graph.nodes()[0]),
            BoundedDataFlowSlice.Direction.FORWARD, 500);
        var backward = BoundedDataFlowSlice.collect(
            List.of(graph.nodes()[500]),
            BoundedDataFlowSlice.Direction.BACKWARD, 500);

        assertFalse(forward.truncated());
        assertNull(forward.truncationReason());
        assertEquals(500, forward.operations().size());
        assertFalse(backward.truncated());
        assertNull(backward.truncationReason());
        assertEquals(500, backward.operations().size());
    }

    @Test
    public void testOverBudgetExplicitlyTruncatesInBothDirections() {
        Chain graph = chain(501);
        var forward = BoundedDataFlowSlice.collect(
            List.of(graph.nodes()[0]),
            BoundedDataFlowSlice.Direction.FORWARD, 500);
        var backward = BoundedDataFlowSlice.collect(
            List.of(graph.nodes()[501]),
            BoundedDataFlowSlice.Direction.BACKWARD, 500);

        assertTrue(forward.truncated());
        assertTrue(backward.truncated());
        assertEquals("operation_budget", forward.truncationReason());
        assertEquals("operation_budget", backward.truncationReason());
        assertEquals(500, forward.operations().size());
        assertEquals(500, backward.operations().size());

        // Repeated observation must contain the same P-code sequence numbers.
        var repeated = BoundedDataFlowSlice.collect(
            List.of(graph.nodes()[0]),
            BoundedDataFlowSlice.Direction.FORWARD, 500);
        assertEquals(sequenceList(forward.operations()),
            sequenceList(repeated.operations()));
    }

    @Test
    public void testForwardOrderIndependentOfDescendantInsertionOrder() {
        VarnodeAST seed = new VarnodeAST(addr(0x01005000L), 4, 1);
        List<PcodeOp> ops = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            VarnodeAST out = new VarnodeAST(addr(0x01005100L + i * 8), 4, i + 2);
            PcodeOp op = new PcodeOp(addr(0x01000300L), i,
                PcodeOp.COPY, new Varnode[] {seed}, out);
            seed.addDescendant(op);
            out.setDef(op);
            ops.add(op);
        }

        var original = BoundedDataFlowSlice.collect(
            List.of(seed), BoundedDataFlowSlice.Direction.FORWARD, 3);
        assertTrue(original.truncated());
        assertEquals("operation_budget", original.truncationReason());

        // The order in Ghidra's linked descendant list is not a selection rule.
        for (PcodeOp op : ops) {
            seed.removeDescendant(op);
        }
        for (int i = ops.size() - 1; i >= 0; i--) {
            seed.addDescendant(ops.get(i));
        }
        var reversed = BoundedDataFlowSlice.collect(
            List.of(seed), BoundedDataFlowSlice.Direction.FORWARD, 3);
        assertEquals(sequenceList(original.operations()),
            sequenceList(reversed.operations()));
        assertEquals(List.of(0, 1, 2),
            original.operations().stream()
                .map(op -> op.getSeqnum().getTime()).toList());
    }

    @Test
    public void testForwardCallRemainsBoundary() {
        VarnodeAST seed = new VarnodeAST(addr(0x01006000L), 8, 1);
        VarnodeAST result = new VarnodeAST(addr(0x01006010L), 8, 2);
        VarnodeAST after = new VarnodeAST(addr(0x01006020L), 8, 3);

        PcodeOp call = new PcodeOp(addr(0x01000310L), 0, PcodeOp.CALL,
            new Varnode[] {seed}, result);
        PcodeOp copy = new PcodeOp(addr(0x01000311L), 1, PcodeOp.COPY,
            new Varnode[] {result}, after);
        result.setDef(call);
        after.setDef(copy);
        seed.addDescendant(call);
        result.addDescendant(copy);

        var forward = BoundedDataFlowSlice.collect(
            List.of(seed), BoundedDataFlowSlice.Direction.FORWARD, 500);
        assertFalse(forward.truncated());
        assertEquals(Set.of(call), forward.operations());

        var backward = BoundedDataFlowSlice.collect(
            List.of(result), BoundedDataFlowSlice.Direction.BACKWARD, 500);
        assertFalse(backward.truncated());
        assertEquals(Set.of(call), backward.operations());
    }

    @Test
    public void testMultipleSeedOrderCannotChangeIncludedOperations() {
        Chain graph = chain(8);
        var a = BoundedDataFlowSlice.collect(
            Arrays.asList(graph.nodes()[0], graph.nodes()[4]),
            BoundedDataFlowSlice.Direction.FORWARD, 4);
        var b = BoundedDataFlowSlice.collect(
            Arrays.asList(graph.nodes()[4], graph.nodes()[0]),
            BoundedDataFlowSlice.Direction.FORWARD, 4);
        assertEquals(sequenceList(a.operations()), sequenceList(b.operations()));
        assertEquals(a.truncated(), b.truncated());
    }

    private static List<String> sequenceList(Set<PcodeOp> operations) {
        return operations.stream()
            .map(op -> op.getSeqnum().toString()).toList();
    }
}
