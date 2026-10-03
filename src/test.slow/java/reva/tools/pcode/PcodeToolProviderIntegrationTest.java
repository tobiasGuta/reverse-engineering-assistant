/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.tools.pcode;

import static org.junit.Assert.*;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Exercises raw P-code extraction on a synthetic x86 function. The test is
 * intentionally self-contained and does not depend on Git LFS fixture binaries.
 */
public class PcodeToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String createBranchFunction() throws Exception {
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        byte[] bytes = {
            (byte) 0x31, (byte) 0xc0,       // xor eax,eax
            (byte) 0x85, (byte) 0xc0,       // test eax,eax
            (byte) 0x74, (byte) 0x03,       // je  +3 -> 0x01000109
            (byte) 0x40,                    // inc eax
            (byte) 0xeb, (byte) 0x01,       // jmp +1 -> 0x0100010a
            (byte) 0x48,                    // dec eax
            (byte) 0xc3                     // ret
        };
        Address end = start.add(bytes.length - 1L);

        int tx = program.startTransaction("create pcode test function");
        try {
            program.getMemory().setBytes(start, bytes);
            DisassembleCommand disassemble = new DisassembleCommand(start, null, true);
            assertTrue("synthetic function should disassemble",
                disassemble.applyTo(program, TaskMonitor.DUMMY));

            FunctionManager manager = program.getFunctionManager();
            assertNotNull("synthetic function should be created",
                manager.createFunction(
                    "pcode_test",
                    start,
                    new AddressSet(start, end),
                    SourceType.USER_DEFINED));
        }
        finally {
            program.endTransaction(tx, true);
        }

        env.open(program);
        ProgramManager programManager = tool.getService(ProgramManager.class);
        assertNotNull("ProgramManager service", programManager);
        programManager.openProgram(program);
        serverManager.programOpened(program, tool);

        return program.getDomainFile().getPathname();
    }

    @Test
    public void testFunctionPcodeReturnsArchitectureNeutralOps() throws Exception {
        String path = createBranchFunction();

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest("get-pcode",
                Map.of(
                    "programPath", path,
                    "target", "pcode_test",
                    "scope", "function",
                    "maxInstructions", 128,
                    "maxOps", 1024)));
            assertMcpResultNotError(result, "get-pcode");

            JsonNode json = parseJsonContent(((TextContent) result.content().get(0)).text());
            assertEquals(path, json.get("programPath").asText());
            assertEquals("function", json.get("scope").asText());
            assertEquals("pcode_test", json.get("function").asText());
            assertTrue(json.get("instructionCount").asInt() > 0);
            assertTrue(json.get("operationCount").asInt() > 0);

            Set<String> opcodes = new HashSet<>();
            for (JsonNode instruction : json.get("instructions")) {
                for (JsonNode op : instruction.get("pcode")) {
                    opcodes.add(op.get("mnemonic").asText());
                }
            }
            assertFalse("Raw P-code should expose operations", opcodes.isEmpty());
            assertTrue("Conditional branch should lift to CBRANCH",
                opcodes.contains("CBRANCH"));
        });
    }

    @Test
    public void testInstructionScopeDoesNotReportFalseTruncation() throws Exception {
        String path = createBranchFunction();

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest("get-pcode",
                Map.of(
                    "programPath", path,
                    "target", "pcode_test",
                    "scope", "instruction",
                    "maxInstructions", 1,
                    "maxOps", 1024)));
            assertMcpResultNotError(result, "get-pcode");

            JsonNode json = parseJsonContent(((TextContent) result.content().get(0)).text());
            assertEquals("instruction", json.get("scope").asText());
            assertEquals(1, json.get("instructionCount").asInt());
            assertFalse("complete instruction scope must not be marked truncated",
                json.get("truncated").asBoolean());
            assertFalse("non-truncated result should not carry a truncation note",
                json.has("note"));
        });
    }

    @Test
    public void testInstructionScopeReportsTrueOpTruncation() throws Exception {
        String path = createBranchFunction();
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000100);
        assertTrue("fixture entry instruction must lift to multiple P-code ops",
            program.getListing().getInstructionAt(start).getPcode().length > 1);

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest("get-pcode",
                Map.of(
                    "programPath", path,
                    "target", "pcode_test",
                    "scope", "instruction",
                    "maxInstructions", 1,
                    "maxOps", 1)));
            assertMcpResultNotError(result, "get-pcode");

            JsonNode json = parseJsonContent(((TextContent) result.content().get(0)).text());
            assertEquals(1, json.get("instructionCount").asInt());
            assertEquals(1, json.get("operationCount").asInt());
            assertTrue("omitted P-code ops must be marked truncated",
                json.get("truncated").asBoolean());
            assertTrue("truncated result should explain the safety bound",
                json.hasNonNull("note"));
        });
    }
}
