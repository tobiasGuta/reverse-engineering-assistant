/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.tools.controlflow;

import static org.junit.Assert.*;

import java.util.Map;

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
 * Exercises CFG extraction on a synthetic branchy x86 function. The test is
 * intentionally self-contained and does not depend on Git LFS fixture binaries.
 */
public class ControlFlowToolProviderIntegrationTest extends RevaIntegrationTestBase {

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

        int tx = program.startTransaction("create branch test function");
        try {
            program.getMemory().setBytes(start, bytes);
            DisassembleCommand disassemble = new DisassembleCommand(start, null, true);
            assertTrue("synthetic function should disassemble",
                disassemble.applyTo(program, TaskMonitor.DUMMY));

            FunctionManager manager = program.getFunctionManager();
            assertNotNull("synthetic function should be created",
                manager.createFunction(
                    "cfg_test",
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
    public void testFunctionCfgOnSyntheticBranchFunction() throws Exception {
        String path = createBranchFunction();

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest("get-function-cfg",
                Map.of("programPath", path, "function", "cfg_test", "maxBlocks", 64)));
            assertMcpResultNotError(result, "get-function-cfg");

            JsonNode json = parseJsonContent(((TextContent) result.content().get(0)).text());
            assertEquals(path, json.get("programPath").asText());
            assertEquals("cfg_test", json.get("function").asText());
            assertTrue("branch function should have multiple basic blocks",
                json.get("blockCount").asInt() >= 3);
            assertTrue(json.get("blocks").isArray());
            assertTrue(json.has("returnedEdgeCount"));
            assertTrue(json.has("returnedCallCount"));
            assertTrue(json.hasNonNull("edgeDefinition"));
            for (JsonNode block : json.get("blocks")) {
                assertTrue(block.has("successorCount"));
                assertTrue(block.get("successors").isArray());
                assertTrue(block.has("callCount"));
                assertTrue(block.get("calls").isArray());
                assertTrue(block.has("referencesTruncated"));
            }
            assertTrue(json.has("cyclomaticComplexity"));
            assertTrue("branch function complexity should exceed straight-line code",
                json.get("cyclomaticComplexity").asInt() >= 2);
        });
    }
}
