/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.tools.stackabi;

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
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Exercises the stack/ABI tools against a self-contained synthetic function.
 * The fixture deliberately defines stack metadata through Ghidra's public model
 * so the test checks the MCP contract rather than a particular decompiler result.
 */
public class StackAbiToolProviderIntegrationTest extends RevaIntegrationTestBase {

    private String createStackAbiFunction() throws Exception {
        return createStackAbiFunction(true, 16);
    }

    private String createStackAbiFunction(
            boolean resolveConvention, int stackPurgeSize) throws Exception {
        Address start = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x01000200);
        byte[] bytes = {
            (byte) 0x90, // nop
            (byte) 0xc3  // ret
        };
        Address end = start.add(bytes.length - 1L);

        int tx = program.startTransaction("create stack ABI test function");
        try {
            program.getMemory().setBytes(start, bytes);
            DisassembleCommand disassemble = new DisassembleCommand(start, null, true);
            assertTrue("synthetic function should disassemble",
                disassemble.applyTo(program, TaskMonitor.DUMMY));

            FunctionManager manager = program.getFunctionManager();
            Function function = manager.createFunction(
                "stack_abi_test",
                start,
                new AddressSet(start, end),
                SourceType.USER_DEFINED);
            assertNotNull("synthetic function should be created", function);

            // A freshly created synthetic function may retain Ghidra's unknown
            // calling-convention state, in which case Function.getCallingConvention()
            // correctly returns null. Resolve it only when the fixture is intended to
            // exercise PrototypeModel-backed ABI facts.
            if (resolveConvention) {
                PrototypeModel defaultConvention =
                    program.getCompilerSpec().getDefaultCallingConvention();
                assertNotNull("compiler spec should define a default calling convention",
                    defaultConvention);
                function.setCallingConvention(defaultConvention.getName());
            }
            function.setStackPurgeSize(stackPurgeSize);

            StackFrame frame = function.getStackFrame();
            frame.setReturnAddressOffset(0);
            assertNotNull("stack local should be created",
                frame.createVariable(
                    "local_test",
                    -0x20,
                    DWordDataType.dataType,
                    SourceType.USER_DEFINED));

            function.setReturnType(DWordDataType.dataType, SourceType.USER_DEFINED);
            function.addParameter(
                new ParameterImpl(
                    "arg0",
                    DWordDataType.dataType,
                    program,
                    SourceType.USER_DEFINED),
                SourceType.USER_DEFINED);
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
    public void testStackFrameReportsGhidraCoordinateSystemAndStorage() throws Exception {
        String path = createStackAbiFunction();

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest(
                "get-function-stack-frame",
                Map.of("programPath", path, "function", "stack_abi_test", "maxVariables", 64)));
            assertMcpResultNotError(result, "get-function-stack-frame");

            JsonNode json = parseJsonContent(((TextContent) result.content().get(0)).text());
            assertEquals(path, json.get("programPath").asText());
            assertEquals("stack_abi_test", json.get("function").asText());
            assertEquals("ghidra-stack-space",
                json.get("frame").get("offsetCoordinateSystem").asText());
            assertTrue(json.get("offsetSemantics").asText().contains("Ghidra stack-space"));
            assertEquals(0, json.get("frame").get("returnAddressOffset").asInt());
            assertTrue(json.get("variables").isArray());

            JsonNode local = null;
            for (JsonNode variable : json.get("variables")) {
                if ("local_test".equals(variable.get("name").asText())) {
                    local = variable;
                    break;
                }
            }
            assertNotNull("local_test should be returned", local);
            assertEquals("local", local.get("kind").asText());
            assertEquals(-0x20, local.get("stackOffset").asInt());
            assertEquals(0x20,
                local.get("byteDeltaFromStackOffsetToReturnAddress").asInt());
            assertEquals("stack", local.get("storage").get("kind").asText());
            assertEquals(-0x20, local.get("storage").get("stackOffset").asInt());
            assertFalse(json.get("truncated").asBoolean());
        });
    }

    @Test
    public void testAbiReportsSignatureConventionAndStorageFacts() throws Exception {
        String path = createStackAbiFunction();

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest(
                "get-function-abi",
                Map.of("programPath", path, "function", "stack_abi_test", "maxParameters", 64)));
            assertMcpResultNotError(result, "get-function-abi");

            JsonNode json = parseJsonContent(((TextContent) result.content().get(0)).text());
            assertEquals(path, json.get("programPath").asText());
            assertEquals("stack_abi_test", json.get("function").asText());

            JsonNode signature = json.get("signature");
            assertTrue(signature.hasNonNull("effectivePrototype"));
            assertTrue(signature.hasNonNull("formalPrototype"));
            assertTrue(signature.hasNonNull("callingConventionName"));
            assertTrue(signature.get("stackPurgeSizeKnown").asBoolean());
            assertEquals(16, signature.get("stackPurgeSize").asInt());

            JsonNode compilerModel = json.get("compilerModel");
            assertTrue(compilerModel.hasNonNull("compilerSpec"));
            assertTrue(compilerModel.has("stackGrowsNegative"));

            assertTrue("resolved test convention should expose a PrototypeModel",
                json.has("callingConvention"));
            JsonNode convention = json.get("callingConvention");
            assertTrue(convention.get("resolved").asBoolean());
            assertTrue(convention.get("unavailableReason").isNull());
            assertTrue(json.get("callingConventionUnavailable").isNull());
            assertTrue(convention.hasNonNull("name"));
            assertTrue(convention.has("stackParameterAlignment"));
            assertTrue(convention.get("stackParameterAlignmentSemantics").asText()
                .contains("individual parameters"));
            assertTrue(convention.get("returnAddressStorage").isArray());
            assertTrue(convention.get("potentialInputRegisterStorage").isArray());

            assertEquals(1, json.get("parameterCount").asInt());
            assertEquals(1, json.get("returnedParameterCount").asInt());
            JsonNode parameter = json.get("parameters").get(0);
            assertEquals("arg0", parameter.get("name").asText());
            assertTrue(parameter.hasNonNull("effectiveDataType"));
            assertTrue(parameter.hasNonNull("formalDataType"));
            assertTrue(parameter.has("storage"));

            JsonNode returnValue = json.get("returnValue");
            assertEquals(-1, returnValue.get("ordinal").asInt());
            assertTrue(returnValue.has("storage"));
            assertFalse(json.get("parametersTruncated").asBoolean());
        });
    }

    @Test
    public void testAbiNormalizesUnresolvedConventionAndUnknownStackPurge() throws Exception {
        String path = createStackAbiFunction(false, Function.UNKNOWN_STACK_DEPTH_CHANGE);

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result = client.callTool(new CallToolRequest(
                "get-function-abi",
                Map.of("programPath", path, "function", "stack_abi_test", "maxParameters", 64)));
            assertMcpResultNotError(result, "get-function-abi");

            JsonNode json = parseJsonContent(((TextContent) result.content().get(0)).text());
            JsonNode signature = json.get("signature");
            assertFalse(signature.get("stackPurgeSizeKnown").asBoolean());
            assertTrue(signature.has("stackPurgeSize"));
            assertTrue(signature.get("stackPurgeSize").isNull());

            JsonNode convention = json.get("callingConvention");
            assertNotNull("callingConvention should remain schema-stable", convention);
            assertFalse(convention.get("resolved").asBoolean());
            assertTrue(convention.get("unavailableReason").asText()
                .contains("no resolved PrototypeModel"));
            assertTrue(json.get("callingConventionUnavailable").asText()
                .contains("no resolved PrototypeModel"));

            assertTrue(convention.has("name"));
            assertTrue(convention.get("name").isNull());
            assertTrue(convention.has("mergedModel"));
            assertTrue(convention.get("mergedModel").isNull());
            assertTrue(convention.has("stackParameterOffset"));
            assertTrue(convention.get("stackParameterOffset").isNull());
            assertTrue(convention.has("stackParameterAlignment"));
            assertTrue(convention.get("stackParameterAlignment").isNull());
            assertTrue(convention.get("stackParameterAlignmentSemantics").asText()
                .contains("individual parameters"));
            assertTrue(convention.has("stackShift"));
            assertTrue(convention.get("stackShift").isNull());
            assertFalse(convention.get("extraPopKnown").asBoolean());
            assertTrue(convention.get("extraPop").isNull());

            for (String key : new String[] {
                "returnAddressStorage",
                "potentialInputRegisterStorage",
                "unaffectedStorage",
                "killedByCallStorage",
                "likelyTrashStorage"
            }) {
                assertTrue(key + " should be present", convention.get(key).isArray());
                assertEquals(0, convention.get(key).size());
                assertEquals(0, convention.get(key + "Count").asInt());
                assertFalse(convention.get(key + "Truncated").asBoolean());
            }
        });
    }
}
