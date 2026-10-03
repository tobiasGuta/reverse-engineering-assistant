/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.tools.program;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.services.ProgramManager;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

public class ProgramIntelligenceToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private void openProgramForMcp() throws Exception {
        // RevaProgramManager discovers programs through Ghidra's ProgramManager.
        // Merely notifying McpServerManager is not enough in headed integration tests.
        env.open(program);
        ProgramManager programManager = tool.getService(ProgramManager.class);
        assertNotNull("ProgramManager service", programManager);
        programManager.openProgram(program);
        serverManager.programOpened(program, tool);
    }

    @Test
    public void testProgramOverviewReturnsBoundedStructuralFacts() throws Exception {
        openProgramForMcp();
        String path = program.getDomainFile().getPathname();

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest("get-program-overview",
                Map.of("programPath", path, "maxBlocks", 16, "maxEntryPoints", 16)));
            assertMcpResultNotError(result, "get-program-overview");

            JsonNode json = parseJsonContent(((TextContent) result.content().get(0)).text());
            assertEquals(path, json.get("programPath").asText());
            assertTrue(json.get("language").asText().contains("x86"));
            assertTrue(json.get("memoryBlockCount").asInt() >= 1);
            assertTrue(json.get("memoryBlocks").isArray());
            assertEquals("default-memory-space", json.get("addressBoundsScope").asText());
            assertTrue(json.hasNonNull("defaultAddressSpace"));
            assertTrue(json.hasNonNull("minAddress"));
            assertTrue(json.hasNonNull("maxAddress"));
            assertEquals(json.get("defaultAddressSpace").asText(),
                json.get("memoryBlocks").get(0).get("addressSpace").asText());
            assertTrue(json.get("functionCount").asInt() >= 0);
            assertTrue(json.has("relocationCount"));
            assertTrue(json.has("sourceFileCount"));
        });
    }
}
