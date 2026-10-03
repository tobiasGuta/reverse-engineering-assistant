/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.tools.sourcemetadata;

import static org.junit.Assert.*;

import java.util.Map;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.services.ProgramManager;
import ghidra.program.database.sourcemap.SourceFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.sourcemap.SourceFileManager;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

public class SourceMetadataToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private void openProgramForMcp() throws Exception {
        env.open(program);
        ProgramManager programManager = tool.getService(ProgramManager.class);
        assertNotNull("ProgramManager service", programManager);
        programManager.openProgram(program);
        serverManager.programOpened(program, tool);
    }

    @Test
    public void testListAndResolveGenericSourceMappings() throws Exception {
        String path = program.getDomainFile().getPathname();
        SourceFileManager manager = program.getSourceFileManager();
        SourceFile source = new SourceFile("/src/example/reva_fixture.c");
        Address address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000010);

        int tx = program.startTransaction("add test source mapping");
        try {
            manager.addSourceFile(source);
            manager.addSourceMapEntry(source, 42, address, 4);
        }
        finally {
            program.endTransaction(tx, true);
        }

        openProgramForMcp();

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();

            CallToolResult listResult = client.callTool(new CallToolRequest("list-source-files",
                Map.of("programPath", path, "query", "reva_fixture", "maxCount", 25)));
            assertMcpResultNotError(listResult, "list-source-files");
            JsonNode listJson = parseJsonContent(((TextContent) listResult.content().get(0)).text());
            assertEquals(1, listJson.get("filteredCount").asInt());
            assertEquals("/src/example/reva_fixture.c",
                listJson.get("files").get(0).get("path").asText());
            assertTrue(listJson.get("files").get(0).get("mapped").asBoolean());

            CallToolResult byFile = client.callTool(new CallToolRequest("get-source-mappings",
                Map.of("programPath", path, "sourcePath", "/src/example/reva_fixture.c")));
            assertMcpResultNotError(byFile, "get-source-mappings by file");
            JsonNode byFileJson = parseJsonContent(((TextContent) byFile.content().get(0)).text());
            assertEquals(1, byFileJson.get("mappingCount").asInt());
            assertEquals(42, byFileJson.get("mappings").get(0).get("line").asInt());
            assertEquals("0x01000010",
                byFileJson.get("mappings").get(0).get("baseAddress").asText());

            CallToolResult byAddress = client.callTool(new CallToolRequest("get-source-mappings",
                Map.of("programPath", path, "addressOrSymbol", "0x01000010")));
            assertMcpResultNotError(byAddress, "get-source-mappings by address");
            JsonNode byAddressJson = parseJsonContent(((TextContent) byAddress.content().get(0)).text());
            assertEquals(1, byAddressJson.get("mappingCount").asInt());
            assertEquals("/src/example/reva_fixture.c",
                byAddressJson.get("mappings").get(0).get("sourcePath").asText());
        });
    }
}
