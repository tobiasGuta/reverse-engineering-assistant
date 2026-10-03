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

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.AnalyzedFixtureSupport;
import reva.RevaIntegrationTestBase;

public class PcodeToolProviderIntegrationTest extends RevaIntegrationTestBase {

    @Test
    public void testFunctionPcodeReturnsArchitectureNeutralOps() throws Exception {
        String path = AnalyzedFixtureSupport.importAndAnalyze(this, "test_dataflow_x86_64");

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest("get-pcode",
                Map.of(
                    "programPath", path,
                    "target", "_transform",
                    "scope", "function",
                    "maxInstructions", 128,
                    "maxOps", 1024)));
            assertMcpResultNotError(result, "get-pcode");

            JsonNode json = parseJsonContent(((TextContent) result.content().get(0)).text());
            assertEquals(path, json.get("programPath").asText());
            assertEquals("function", json.get("scope").asText());
            assertEquals("_transform", json.get("function").asText());
            assertTrue(json.get("instructionCount").asInt() > 0);
            assertTrue(json.get("operationCount").asInt() > 0);

            Set<String> opcodes = new HashSet<>();
            for (JsonNode instruction : json.get("instructions")) {
                for (JsonNode op : instruction.get("pcode")) {
                    opcodes.add(op.get("mnemonic").asText());
                }
            }
            assertFalse("Raw P-code should expose at least one operation", opcodes.isEmpty());
        });
    }
}
