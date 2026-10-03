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

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

public class ProgramIntelligenceToolProviderIntegrationTest extends RevaIntegrationTestBase {

    @Test
    public void testProgramOverviewReturnsBoundedStructuralFacts() throws Exception {
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
            assertTrue(json.get("functionCount").asInt() >= 0);
            assertTrue(json.has("relocationCount"));
            assertTrue(json.has("sourceFileCount"));
        });
    }
}
