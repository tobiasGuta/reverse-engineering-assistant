/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.tools.callboundary;

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

/**
 * Synthetic x86-64 native machine-code fixture. Exercises both concrete
 * calls and unresolved indirect calls through the actual MCP transport.
 */
public class CallBoundaryToolProviderIntegrationTest
        extends RevaIntegrationTestBase {
    private static final long MAIN = 0x01000300L;
    private static final long CALLEE = 0x01000320L;
    private static final long INDIRECT = 0x01000360L;

    private String openFixture() throws Exception {
        Address main = address(MAIN);
        Address callee = address(CALLEE);
        Address indirect = address(INDIRECT);
        // push rbp; mov rbp,rsp; call 0x01000320; pop rbp; ret
        byte[] callerBytes = {
            (byte) 0x55, (byte) 0x48, (byte) 0x89, (byte) 0xe5,
            (byte) 0xe8, (byte) 0x17, 0, 0, 0,
            (byte) 0x5d, (byte) 0xc3
        };
        // push rbp; mov rbp,rsp; mov eax,edi; add eax,7; pop rbp; ret
        byte[] calleeBytes = {
            (byte) 0x55, (byte) 0x48, (byte) 0x89, (byte) 0xe5,
            (byte) 0x89, (byte) 0xf8,
            (byte) 0x83, (byte) 0xc0, (byte) 0x07,
            (byte) 0x5d, (byte) 0xc3
        };
        // call rax; ret -- no supported target identity should be invented
        byte[] indirectBytes = {
            (byte) 0xff, (byte) 0xd0, (byte) 0xc3
        };

        int transaction = program.startTransaction("create Slice 5A fixture");
        try {
            program.getMemory().setBytes(main, callerBytes);
            program.getMemory().setBytes(callee, calleeBytes);
            program.getMemory().setBytes(indirect, indirectBytes);

            assertTrue(new DisassembleCommand(main, null, true)
                .applyTo(program, TaskMonitor.DUMMY));
            assertTrue(new DisassembleCommand(callee, null, true)
                .applyTo(program, TaskMonitor.DUMMY));
            assertTrue(new DisassembleCommand(indirect, null, true)
                .applyTo(program, TaskMonitor.DUMMY));

            FunctionManager functions = program.getFunctionManager();
            Function target = functions.createFunction("transform", callee,
                new AddressSet(callee, callee.add(calleeBytes.length - 1L)),
                SourceType.USER_DEFINED);
            Function source = functions.createFunction("main", main,
                new AddressSet(main, main.add(callerBytes.length - 1L)),
                SourceType.USER_DEFINED);
            Function pointerCaller =
                functions.createFunction("pointerCaller", indirect,
                    new AddressSet(indirect,
                        indirect.add(indirectBytes.length - 1L)),
                    SourceType.USER_DEFINED);
            assertNotNull(target);
            assertNotNull(source);
            assertNotNull(pointerCaller);

            PrototypeModel convention =
                program.getCompilerSpec().getDefaultCallingConvention();
            assertNotNull(convention);
            for (Function function :
                    new Function[] { target, source, pointerCaller }) {
                function.setCallingConvention(convention.getName());
            }
            target.setReturnType(
                DWordDataType.dataType, SourceType.USER_DEFINED);
            target.addParameter(new ParameterImpl(
                    "seed", DWordDataType.dataType, program,
                    SourceType.USER_DEFINED),
                SourceType.USER_DEFINED);
            source.setReturnType(
                DWordDataType.dataType, SourceType.USER_DEFINED);
            source.addParameter(new ParameterImpl(
                    "seed", DWordDataType.dataType, program,
                    SourceType.USER_DEFINED),
                SourceType.USER_DEFINED);
        }
        finally {
            program.endTransaction(transaction, true);
        }

        env.open(program);
        ProgramManager programManager = tool.getService(ProgramManager.class);
        assertNotNull(programManager);
        programManager.openProgram(program);
        serverManager.programOpened(program, tool);
        return program.getDomainFile().getPathname();
    }

    private Address address(long offset) {
        return program.getAddressFactory()
            .getDefaultAddressSpace().getAddress(offset);
    }

    private JsonNode inspect(String path, long callsite, int maxArguments)
            throws Exception {
        return withMcpClient(createMcpTransport(),
            (McpClientFunction<JsonNode>) client -> {
                client.initialize();
                CallToolResult response = client.callTool(
                    new CallToolRequest("inspect-call-boundary",
                        Map.of("programPath", path,
                            "callsite", address(callsite).toString(),
                            "maxArguments", maxArguments)));
                assertMcpResultNotError(response, "inspect-call-boundary");
                return parseJsonContent(
                    ((TextContent) response.content().get(0)).text());
            });
    }

    @Test
    public void testDirectCallReportsDistinctCallerAndCalleeEvidence()
            throws Exception {
        String path = openFixture();
        JsonNode report = inspect(path, MAIN + 4, 16);

        assertEquals("main", report.path("caller").path("name").asText());
        assertFalse(report.path("callOperationsTruncated").asBoolean());
        assertEquals(1, report.path("callOperationCount").asInt());

        JsonNode call = report.path("calls").get(0);
        assertEquals("CALL", call.path("opcode").asText());
        assertEquals("direct_internal", call.path("targetKind").asText());
        assertEquals("transform", call.path("callee").path("name").asText());
        assertEquals(1, call.path("formalParameterCount").asInt());
        assertFalse(call.path("argumentsTruncated").asBoolean());
        assertTrue(call.path("argumentCount").asInt() >= 1);
        assertTrue(call.path("calleeReturnSiteCount").asInt() >= 1);
        assertNotEquals("runtime_verified",
            call.path("mappingStatus").asText());
        assertTrue(report.path("semantics").asText().contains(
            "not runtime observations"));
        if ("decompiler_positional_candidate".equals(
                call.path("mappingStatus").asText())) {
            assertEquals(0,
                call.path("arguments").get(0)
                    .path("candidateFormalIndex").asInt());
        }
    }

    @Test
    public void testIndirectTargetIsNotInvented() throws Exception {
        String path = openFixture();
        JsonNode report = inspect(path, INDIRECT, 16);
        assertEquals(1, report.path("callOperationCount").asInt());

        JsonNode call = report.path("calls").get(0);
        assertEquals("CALLIND", call.path("opcode").asText());
        assertEquals("indirect_unresolved",
            call.path("targetKind").asText());
        assertTrue(call.path("callee").isNull());
        assertEquals("unavailable_indirect_target",
            call.path("mappingStatus").asText());
        assertFalse(call.has("candidateFormalIndex"));
    }

    @Test
    public void testNonCallInstructionAndInvalidLimitAreRejected()
            throws Exception {
        String path = openFixture();
        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            for (Map<String, Object> request : new Map[] {
                Map.of("programPath", path,
                    "callsite", address(MAIN).toString()),
                Map.of("programPath", path,
                    "callsite", address(MAIN + 4).toString(),
                    "maxArguments", 129)
            }) {
                CallToolResult response = client.callTool(
                    new CallToolRequest("inspect-call-boundary", request));
                assertTrue("invalid request must be rejected",
                    response.isError());
            }
        });
    }
}
