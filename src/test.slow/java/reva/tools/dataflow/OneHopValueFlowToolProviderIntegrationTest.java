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

import java.util.Map;

import org.junit.Test;
import com.fasterxml.jackson.databind.JsonNode;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/** One-hop MCP regression against real x86-64 machine instructions. */
public class OneHopValueFlowToolProviderIntegrationTest
        extends RevaIntegrationTestBase {
    private static final long CALLER = 0x01000300L;
    private static final long CALLEE = 0x01000320L;
    private static final long INDIRECT = 0x01000360L;

    private Address address(long a) {
        return program.getAddressFactory().getDefaultAddressSpace().getAddress(a);
    }

    private String openFixture() throws Exception {
        Address caller = address(CALLER);
        Address callee = address(CALLEE);
        Address indirect = address(INDIRECT);
        // push rbp; mov rbp,rsp; call 0x01000320; pop rbp; ret
        byte[] callerBytes = {
            (byte) 0x55, (byte) 0x48, (byte) 0x89, (byte) 0xe5,
            (byte) 0xe8, (byte) 0x17, 0, 0, 0, (byte) 0x5d, (byte) 0xc3
        };
        // push rbp; mov rbp,rsp; mov eax,edi; add eax,7; pop rbp; ret
        byte[] calleeBytes = {
            (byte) 0x55, (byte) 0x48, (byte) 0x89, (byte) 0xe5,
            (byte) 0x89, (byte) 0xf8,
            (byte) 0x83, (byte) 0xc0, (byte) 0x07,
            (byte) 0x5d, (byte) 0xc3
        };
        byte[] indirectBytes = {(byte) 0xff, (byte) 0xd0, (byte) 0xc3};

        int tx = program.startTransaction("one-hop synthetic fixture");
        try {
            program.getMemory().setBytes(caller, callerBytes);
            program.getMemory().setBytes(callee, calleeBytes);
            program.getMemory().setBytes(indirect, indirectBytes);
            assertTrue(new DisassembleCommand(
                caller, null, true).applyTo(program, TaskMonitor.DUMMY));
            assertTrue(new DisassembleCommand(
                callee, null, true).applyTo(program, TaskMonitor.DUMMY));
            assertTrue(new DisassembleCommand(
                indirect, null, true).applyTo(program, TaskMonitor.DUMMY));

            FunctionManager functions = program.getFunctionManager();
            Function source = functions.createFunction(
                "oneHopCaller", caller,
                new AddressSet(caller, caller.add(callerBytes.length - 1L)),
                SourceType.USER_DEFINED);
            Function target = functions.createFunction(
                "oneHopTarget", callee,
                new AddressSet(callee, callee.add(calleeBytes.length - 1L)),
                SourceType.USER_DEFINED);
            Function pointer = functions.createFunction(
                "oneHopIndirect", indirect,
                new AddressSet(indirect, indirect.add(indirectBytes.length - 1L)),
                SourceType.USER_DEFINED);
            assertNotNull(source);
            assertNotNull(target);
            assertNotNull(pointer);

            PrototypeModel model =
                program.getCompilerSpec().getDefaultCallingConvention();
            assertNotNull(model);
            for (Function f : new Function[]{source, target, pointer}) {
                f.setCallingConvention(model.getName());
            }
            target.setReturnType(
                DWordDataType.dataType, SourceType.USER_DEFINED);
            target.addParameter(
                new ParameterImpl("seed", DWordDataType.dataType, program,
                    SourceType.USER_DEFINED),
                SourceType.USER_DEFINED);
            source.setReturnType(
                DWordDataType.dataType, SourceType.USER_DEFINED);
            source.addParameter(
                new ParameterImpl("seed", DWordDataType.dataType, program,
                    SourceType.USER_DEFINED),
                SourceType.USER_DEFINED);
        }
        finally {
            program.endTransaction(tx, true);
        }

        env.open(program);
        ProgramManager manager = tool.getService(ProgramManager.class);
        assertNotNull(manager);
        manager.openProgram(program);
        serverManager.programOpened(program, tool);
        return program.getDomainFile().getPathname();
    }

    private JsonNode trace(String programPath, long callsite,
            int argIndex, int maxOperations) throws Exception {
        return withMcpClient(createMcpTransport(),
            (McpClientFunction<JsonNode>) client -> {
                client.initialize();
                CallToolResult response = client.callTool(
                    new CallToolRequest("trace-call-argument-one-hop",
                        Map.of("programPath", programPath,
                            "callsite", address(callsite).toString(),
                            "argumentIndex", argIndex,
                            "maxOperations", maxOperations)));
                assertMcpResultNotError(response, "trace-call-argument-one-hop");
                return parseJsonContent(
                    ((TextContent) response.content().get(0)).text());
            });
    }

    @Test
    public void testDirectCallRetainsTwoIndependentGraphs() throws Exception {
        String path = openFixture();
        JsonNode report = trace(path, CALLER + 4L, 0, 16);
        assertEquals("oneHopCaller",
            report.path("caller").path("name").asText());
        assertEquals("oneHopTarget",
            report.path("callee").path("name").asText());
        assertEquals("CALL", report.path("opcode").asText());
        assertEquals(0, report.path("argumentIndex").asInt());
        assertEquals(1, report.path("argumentCount").asInt());
        assertEquals("decompiler_positional_candidate",
            report.path("relationStatus").asText());
        assertTrue(report.path("relationSemantics").asText()
            .contains("never a runtime-proven"));
        assertEquals(0, report.path("calleeFormal").path("slot").asInt());
        assertTrue(report.path("callerEvidence").isObject());
        assertTrue(report.path("calleeEvidence").isObject());
        assertEquals("oneHopCaller",
            report.path("callerEvidence").path("function").path("name").asText());
        assertEquals("oneHopTarget",
            report.path("calleeEvidence").path("function").path("name").asText());
        assertFalse(report.path("callerEvidence").path("truncated").asBoolean());
        assertFalse(report.path("calleeEvidence").path("truncated").asBoolean());
        assertTrue(report.path("complete").asBoolean());
    }

    @Test
    public void testIndirectCallHasNoCalleeJoin() throws Exception {
        String path = openFixture();
        JsonNode report = trace(path, INDIRECT, 0, 16);
        // An indirect call may have 0 arguments in this synthetic fixture;
        // in that case its argument selection is correctly unavailable.
        String status = report.path("relationStatus").asText();
        assertTrue(status,
            status.equals("unavailable_indirect_target") ||
            status.equals("unavailable_argument_index"));
        assertFalse(report.path("complete").asBoolean());
        assertTrue(report.path("calleeEvidence").isNull());
    }

    @Test
    public void testVariadicCalleeNeverJoins() throws Exception {
        String path = openFixture();
        int tx = program.startTransaction("variadic one-hop negative control");
        try {
            Function callee =
                program.getFunctionManager().getFunctionAt(address(CALLEE));
            callee.setVarArgs(true);
        }
        finally {
            program.endTransaction(tx, true);
        }
        JsonNode report = trace(path, CALLER + 4L, 0, 16);
        assertEquals("ambiguous_prototype_or_storage",
            report.path("relationStatus").asText());
        assertTrue(report.path("callerEvidence").isObject());
        assertTrue(report.path("calleeEvidence").isNull());
        assertFalse(report.path("complete").asBoolean());
    }

    @Test
    public void testInvalidArgumentAndOperationLimitFailClosed() throws Exception {
        String path = openFixture();
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            for (Map<String, Object> params : new Map[] {
                Map.of("programPath", path,
                    "callsite", address(CALLER + 4L).toString(),
                    "argumentIndex", -1),
                Map.of("programPath", path,
                    "callsite", address(CALLER + 4L).toString(),
                    "argumentIndex", 0, "maxOperations", 501),
                Map.of("programPath", path,
                    "callsite", address(CALLER).toString(),
                    "argumentIndex", 0)
            }) {
                CallToolResult response = client.callTool(
                    new CallToolRequest("trace-call-argument-one-hop", params));
                assertTrue("invalid request must be rejected",
                    response.isError());
            }
        });
    }
}
