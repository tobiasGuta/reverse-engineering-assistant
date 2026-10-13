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

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Test;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;
import reva.util.AddressUtil;

/** Read-only two-hop MCP regressions with known x86-64 direct-call fixture. */
public class TwoHopValueFlowToolProviderIntegrationTest
        extends RevaIntegrationTestBase {
    private static final long A = 0x01000300L;
    private static final long B = 0x01000320L;
    private static final long C = 0x01000350L;
    private static final long A_CALL = A + 4;
    private static final long B_CALL = B + 7;

    private Address addr(long n) {
        return program.getAddressFactory()
            .getDefaultAddressSpace().getAddress(n);
    }

    private String openChain() throws Exception {
        // A: push rbp; mov rbp,rsp; call B; pop rbp; ret
        byte[] a = {(byte)0x55,(byte)0x48,(byte)0x89,(byte)0xe5,
            (byte)0xe8,(byte)0x17,0,0,0,(byte)0x5d,(byte)0xc3};
        // B: push rbp; mov rbp,rsp; add edi,2; call C; pop rbp; ret
        byte[] b = {(byte)0x55,(byte)0x48,(byte)0x89,(byte)0xe5,
            (byte)0x83,(byte)0xc7,(byte)0x02,
            (byte)0xe8,(byte)0x24,0,0,0,(byte)0x5d,(byte)0xc3};
        // C: push rbp; mov rbp,rsp; mov eax,edi; add eax,7; pop rbp; ret
        byte[] c = {(byte)0x55,(byte)0x48,(byte)0x89,(byte)0xe5,
            (byte)0x89,(byte)0xf8,(byte)0x83,(byte)0xc0,(byte)0x07,
            (byte)0x5d,(byte)0xc3};
        int tx = program.startTransaction("two-hop fixture");
        try {
            for (int i = 0; i < 3; i++) {
                long entry = i == 0 ? A : i == 1 ? B : C;
                byte[] bytes = i == 0 ? a : i == 1 ? b : c;
                program.getMemory().setBytes(addr(entry), bytes);
                assertTrue(new DisassembleCommand(addr(entry), null, true)
                    .applyTo(program, TaskMonitor.DUMMY));
            }
            FunctionManager manager = program.getFunctionManager();
            Function fnA = manager.createFunction("chainA", addr(A),
                new AddressSet(addr(A),addr(A+a.length-1L)),
                SourceType.USER_DEFINED);
            Function fnB = manager.createFunction("chainB", addr(B),
                new AddressSet(addr(B),addr(B+b.length-1L)),
                SourceType.USER_DEFINED);
            Function fnC = manager.createFunction("chainC", addr(C),
                new AddressSet(addr(C),addr(C+c.length-1L)),
                SourceType.USER_DEFINED);
            PrototypeModel model =
                program.getCompilerSpec().getDefaultCallingConvention();
            assertNotNull(model);
            for (Function f : new Function[]{fnA,fnB,fnC}) {
                f.setCallingConvention(model.getName());
                f.setReturnType(DWordDataType.dataType,
                    SourceType.USER_DEFINED);
                f.addParameter(new ParameterImpl(
                    "value", DWordDataType.dataType, program,
                    SourceType.USER_DEFINED), SourceType.USER_DEFINED);
            }
        }
        finally {
            program.endTransaction(tx, true);
        }
        env.open(program);
        ProgramManager service = tool.getService(ProgramManager.class);
        assertNotNull(service);
        service.openProgram(program);
        serverManager.programOpened(program, tool);
        return program.getDomainFile().getPathname();
    }

    private JsonNode trace(String path, int budget, int reported)
            throws Exception {
        return withMcpClient(createMcpTransport(),
            (McpClientFunction<JsonNode>) client -> {
                client.initialize();
                CallToolResult response = client.callTool(
                    new CallToolRequest("trace-call-argument-two-hop",
                        Map.of("programPath", path,
                            "callsite", addr(A_CALL).toString(),
                            "argumentIndex", 0,
                            "maxOperations", budget,
                            "maxReportedOperations", reported)));
                assertMcpResultNotError(response,
                    "trace-call-argument-two-hop");
                return parseJsonContent(
                    ((TextContent)response.content().get(0)).text());
            });
    }

    @Test
    public void testTwoDirectKnownSignatureCallsPreserveSeparateEvidence()
            throws Exception {
        String path = openChain();
        JsonNode result = trace(path, 64, 12);
        assertEquals("decompiler_positional_candidate",
            result.path("firstBoundaryStatus").asText());
        assertEquals("chainB",
            result.path("intermediateFunction").path("name").asText());
        assertTrue(result.path("callerArgumentEvidence").isObject());
        assertTrue(result.path("intermediateFormalEvidence").isObject());
        assertTrue(result.path("semantics").asText()
            .contains("NO proven runtime"));
        JsonNode candidates = result.path("candidateSecondHops");
        assertTrue("B should forward its parameter to C", candidates.size() > 0);
        boolean found = false;
        for (JsonNode candidate : candidates) {
            if ("decompiler_positional_candidate".equals(
                    candidate.path("boundaryStatus").asText()) &&
                "chainC".equals(candidate.path("callee").path("name").asText())) {
                found = true;
                assertEquals(AddressUtil.formatAddress(addr(B_CALL)),
                    candidate.path("callsite").asText());
                assertEquals(0,candidate.path("argumentIndex").asInt());
                assertEquals("observed_ssa_dependency_candidate",
                    candidate.path("intermediateDependency").asText());
                assertTrue(candidate.path("intermediateArgumentEvidence")
                    .isObject());
                assertTrue(candidate.path("calleeFormalEvidence").isObject());
            }
        }
        assertTrue("B->C candidate must retain C formal evidence", found);
    }

    @Test
    public void testVariadicSecondPrototypeCannotProduceCandidate()
            throws Exception {
        String path = openChain();
        int tx = program.startTransaction("variadic C prototype test");
        try {
            program.getFunctionManager().getFunctionAt(addr(C))
                .setVarArgs(true);
        }
        finally {
            program.endTransaction(tx, true);
        }
        JsonNode result = trace(path, 64, 12);
        assertEquals("decompiler_positional_candidate",
            result.path("firstBoundaryStatus").asText());
        for (JsonNode candidate : result.path("candidateSecondHops")) {
            assertNotEquals("decompiler_positional_candidate",
                candidate.path("boundaryStatus").asText());
            assertFalse(candidate.path("complete").asBoolean());
            assertTrue(candidate.path("calleeFormalEvidence").isMissingNode());
        }
        assertFalse(result.path("complete").asBoolean());
    }

    @Test
    public void testSsaForwardingNeverTraversesLoadOrCallResults() {
        VarnodeAST input = new VarnodeAST(addr(0x01005000L), 4, 1);
        VarnodeAST copied = new VarnodeAST(addr(0x01005008L), 4, 2);
        VarnodeAST loaded = new VarnodeAST(addr(0x01005010L), 4, 3);
        VarnodeAST computed = new VarnodeAST(addr(0x01005018L), 4, 4);
        VarnodeAST afterCall = new VarnodeAST(addr(0x01005020L), 4, 5);
        Varnode constant = new Varnode(addr(0x01L), 4);
        PcodeOp copy = new PcodeOp(addr(0x01000400L), 1,
            PcodeOp.COPY, new Varnode[]{input}, copied);
        PcodeOp load = new PcodeOp(addr(0x01000401L), 2,
            PcodeOp.LOAD, new Varnode[]{constant,copied}, loaded);
        PcodeOp add = new PcodeOp(addr(0x01000402L), 3,
            PcodeOp.INT_ADD, new Varnode[]{copied,constant},computed);
        PcodeOp unknownCall = new PcodeOp(addr(0x01000403L), 4,
            PcodeOp.CALL, new Varnode[]{constant,computed},afterCall);
        PcodeOp safeCall = new PcodeOp(addr(0x01000404L), 5,
            PcodeOp.CALL, new Varnode[]{constant,loaded},null);
        PcodeOp resultCall = new PcodeOp(addr(0x01000405L), 6,
            PcodeOp.CALL, new Varnode[]{constant,afterCall},null);
        Set<PcodeOp> observed = new LinkedHashSet<>(
            List.of(copy, load, add, unknownCall, safeCall, resultCall));
        var hits=TwoHopValueFlowToolProvider.observedForwardedArguments(
            List.of(input), observed);
        assertEquals(1, hits.size());
        assertEquals(unknownCall, hits.get(0).call());
        assertEquals(0, hits.get(0).argumentIndex());
    }
}
