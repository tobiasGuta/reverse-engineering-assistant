/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */
package reva.tools.dataflow;

import static org.junit.Assert.*;

import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import org.junit.Test;

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
import reva.util.AddressUtil;

/**
 * Synthetic x86-32 memory-store/load fixture, never executed.
 * The intervening direct call prevents treating two memory operations as
 * automatically equivalent values; any store is a candidate only.
 */
public class MemoryOriginCandidateToolProviderIntegrationTest
        extends RevaIntegrationTestBase {
    private static final long F = 0x01000300L;
    private static final long HELPER = 0x01000350L;
    private static final long STORE = F + 7;
    private static final long LOAD = F + 22;
    private static final long RELATED_STORE = F + 24;

    private Address addr(long n) {
        return program.getAddressFactory().getDefaultAddressSpace()
            .getAddress(n);
    }

    private String openMemoryFixture() throws Exception {
        // push ebp; mov ebp,esp; push esi; mov esi,[ebp+8];
        // mov dword ptr [esi],7; push esi; call helper;
        // add esp,4; mov eax,[esi]; mov dword ptr [esi+8],9;
        // pop esi; pop ebp; ret
        byte[] function = new byte[] {
            (byte)0x55, (byte)0x89, (byte)0xe5, (byte)0x56,
            (byte)0x8b, (byte)0x75, (byte)0x08,
            (byte)0xc7, (byte)0x06, (byte)0x07, 0, 0, 0,
            (byte)0x56,
            (byte)0xe8, (byte)0x3d, 0, 0, 0,
            (byte)0x83, (byte)0xc4, (byte)0x04,
            (byte)0x8b, (byte)0x06,
            (byte)0xc7, (byte)0x46, (byte)0x08,
            (byte)0x09, 0, 0, 0,
            (byte)0x5e, (byte)0x5d, (byte)0xc3
        };
        byte[] helper = new byte[] { (byte)0xc3 };
        int tx = program.startTransaction("memory-origin fixture");
        try {
            program.getMemory().setBytes(addr(F), function);
            program.getMemory().setBytes(addr(HELPER), helper);
            assertTrue(new DisassembleCommand(addr(HELPER), null, true)
                .applyTo(program, TaskMonitor.DUMMY));
            assertTrue(new DisassembleCommand(addr(F), null, true)
                .applyTo(program, TaskMonitor.DUMMY));
            FunctionManager manager = program.getFunctionManager();
            manager.createFunction("memoryProbe", addr(F),
                new AddressSet(addr(F), addr(F + function.length - 1L)),
                SourceType.USER_DEFINED);
            manager.createFunction("probeHelper", addr(HELPER),
                new AddressSet(addr(HELPER), addr(HELPER)),
                SourceType.USER_DEFINED);
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

    private JsonNode trace(String path, int maxScan) throws Exception {
        return withMcpClient(createMcpTransport(),
            (McpClientFunction<JsonNode>) client -> {
                client.initialize();
                CallToolResult response = client.callTool(
                    new CallToolRequest("trace-memory-load-origins",
                        Map.of("programPath", path,
                            "loadAddress", addr(LOAD).toString(),
                            "maxScannedOperations", maxScan,
                            "maxSliceOperations", 64,
                            "maxReportedOperations", 8)));
                assertMcpResultNotError(response, "trace-memory-load-origins");
                return parseJsonContent(
                    ((TextContent)response.content().get(0)).text());
            });
    }

    @Test
    public void testCandidateStoreDoesNotClaimMemoryProvenance() throws Exception {
        String path = openMemoryFixture();
        JsonNode result = trace(path, 2048);
        assertEquals("syntactic_store_candidates_only",
            result.path("status").asText());
        assertEquals(AddressUtil.formatAddress(addr(LOAD)),
            result.path("loadAddress").asText());
        assertTrue("Candidate store absent: " + result,
            result.path("candidateStores").size() >= 1);
        boolean found = false;
        for (JsonNode item : result.path("candidateStores")) {
            if (AddressUtil.formatAddress(addr(STORE)).equals(
                item.path("storeAddress").asText())) {
                found = true;
                assertEquals("unproven",
                    item.path("reachingDefinition").asText());
                assertTrue(item.path("storedValueEvidence").isObject());
            }
        }
        assertTrue("STORE at known machine address not observed: " + result,
            found);
        assertFalse(result.path("memoryOriginResolved").asBoolean());
        assertEquals(0, result.path("provenReachingDefinitions").asInt());
        assertTrue(result.path("loadPointerTerm").isObject());
        assertTrue(result.path("totalStoreOperationsObserved").asInt() >= 1);
        assertTrue(result.path("storesInLoadMemorySpace").asInt() >= 1);
        assertTrue(result.path("observedStoreSample").isArray());
        assertTrue(result.path("observedStoreSample").size() >= 1);
        assertTrue(result.path("storeSampleSemantics").asText()
            .contains("NOT candidate reaching definitions"));
        assertTrue(result.path("enumerationComplete").asBoolean());
        assertTrue(result.path("sameBaseDifferentOffsetStores").isArray());
        assertTrue("Expected distinct-offset lead: " + result,
            result.path("sameBaseDifferentOffsetStoreCount").asInt() >= 1);
        boolean relatedFound = false;
        for (JsonNode related : result.path("sameBaseDifferentOffsetStores")) {
            if (AddressUtil.formatAddress(addr(RELATED_STORE)).equals(
                    related.path("storeAddress").asText())) {
                relatedFound = true;
                assertEquals("same_ssa_base_distinct_static_offset",
                    related.path("relation").asText());
                assertFalse(related.path("sameMemoryAddress").asBoolean());
                assertEquals("unproven",
                    related.path("reachingDefinition").asText());
                assertEquals(8,
                    related.path("relativeOffsetBytes").asInt());
            }
        }
        assertTrue("Distinct-offset STORE lead missing: " + result,
            relatedFound);
    }

    @Test
    public void testScanBudgetFailsClosed() throws Exception {
        String path = openMemoryFixture();
        JsonNode result = trace(path, 1);
        assertEquals("incomplete_scan_budget",
            result.path("status").asText());
        assertTrue(result.path("scanTruncated").asBoolean());
        assertFalse(result.path("enumerationComplete").asBoolean());
        assertFalse(result.path("memoryOriginResolved").asBoolean());
    }

    @Test
    public void testNoHighLoadAddressIsExplicitlyUnavailable() throws Exception {
        String path = openMemoryFixture();
        JsonNode result = withMcpClient(createMcpTransport(),
            (McpClientFunction<JsonNode>) client -> {
                client.initialize();
                CallToolResult response = client.callTool(
                    new CallToolRequest("trace-memory-load-origins",
                        Map.of("programPath", path,
                            "loadAddress", addr(STORE).toString())));
                assertMcpResultNotError(response, "trace-memory-load-origins");
                return parseJsonContent(
                    ((TextContent)response.content().get(0)).text());
            });
        assertEquals("unavailable_high_pcode_load",
            result.path("status").asText());
        assertEquals(0, result.path("candidateStores").size());
    }
}
