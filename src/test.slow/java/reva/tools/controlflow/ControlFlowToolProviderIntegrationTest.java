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

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.AnalyzedFixtureSupport;
import reva.RevaIntegrationTestBase;

public class ControlFlowToolProviderIntegrationTest extends RevaIntegrationTestBase {

    @Test
    public void testFunctionCfgOnAnalyzedFixture() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, "test_dataflow_x86_64");

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest("get-function-cfg",
                Map.of("programPath", path, "function", "_transform", "maxBlocks", 64)));
            assertMcpResultNotError(result, "get-function-cfg");

            JsonNode json = parseJsonContent(((TextContent) result.content().get(0)).text());
            assertEquals(path, json.get("programPath").asText());
            assertEquals("_transform", json.get("function").asText());
            assertTrue(json.get("blockCount").asInt() > 0);
            assertTrue(json.get("blocks").isArray());
            assertTrue(json.has("cyclomaticComplexity"));
            assertTrue(json.get("cyclomaticComplexity").asInt() >= 1);
        });
    }
}
