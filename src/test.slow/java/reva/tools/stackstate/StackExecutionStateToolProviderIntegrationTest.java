/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.tools.stackstate;

import static org.junit.Assert.*;

import java.util.List;
import java.util.Map;

import org.junit.Test;

import com.fasterxml.jackson.databind.JsonNode;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Exercises per-instruction stack state on a self-contained x86-32 function.
 *
 * main:
 *   push ebp
 *   mov  ebp,esp
 *   sub  esp,0x20
 *   mov  eax,[ebp-4]
 *   call target
 *   add  esp,0x20
 *   pop  ebp
 *   ret
 */
public class StackExecutionStateToolProviderIntegrationTest
        extends RevaIntegrationTestBase {

    private static final long MAIN_ADDRESS = 0x01000400L;
    private static final long TARGET_ADDRESS = 0x01000420L;

    private String createStackStateFixture() throws Exception {
        Address mainStart =
            program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(MAIN_ADDRESS);
        Address targetStart =
            program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(TARGET_ADDRESS);

        byte[] mainBytes = {
            (byte) 0x55,                         // push ebp
            (byte) 0x89, (byte) 0xe5,            // mov ebp,esp
            (byte) 0x83, (byte) 0xec, (byte) 0x20, // sub esp,0x20
            (byte) 0x8b, (byte) 0x45, (byte) 0xfc, // mov eax,[ebp-4]
            (byte) 0xe8, (byte) 0x12, (byte) 0x00,
                (byte) 0x00, (byte) 0x00,        // call 0x01000420
            (byte) 0x83, (byte) 0xc4, (byte) 0x20, // add esp,0x20
            (byte) 0x5d,                         // pop ebp
            (byte) 0xc3                          // ret
        };

        byte[] targetBytes = {
            (byte) 0xc3
        };

        Address mainEnd =
            mainStart.add(mainBytes.length - 1L);
        Address targetEnd =
            targetStart.add(targetBytes.length - 1L);

        int tx =
            program.startTransaction(
                "create stack execution state fixture");
        try {
            program.getMemory().setBytes(mainStart, mainBytes);
            program.getMemory().setBytes(
                targetStart, targetBytes);

            assertTrue(
                new DisassembleCommand(
                    mainStart, null, true)
                    .applyTo(program, TaskMonitor.DUMMY));
            assertTrue(
                new DisassembleCommand(
                    targetStart, null, true)
                    .applyTo(program, TaskMonitor.DUMMY));

            FunctionManager manager =
                program.getFunctionManager();
            Function target = manager.createFunction(
                "stack_state_target",
                targetStart,
                new AddressSet(targetStart, targetEnd),
                SourceType.USER_DEFINED);
            Function main = manager.createFunction(
                "stack_state_main",
                mainStart,
                new AddressSet(mainStart, mainEnd),
                SourceType.USER_DEFINED);

            assertNotNull(target);
            assertNotNull(main);

            PrototypeModel defaultConvention =
                program.getCompilerSpec()
                    .getDefaultCallingConvention();
            assertNotNull(defaultConvention);
            target.setCallingConvention(
                defaultConvention.getName());
            main.setCallingConvention(
                defaultConvention.getName());
        }
        finally {
            program.endTransaction(tx, true);
        }

        env.open(program);
        ProgramManager programManager =
            tool.getService(ProgramManager.class);
        assertNotNull(programManager);
        programManager.openProgram(program);
        serverManager.programOpened(program, tool);

        return program.getDomainFile().getPathname();
    }

    private JsonNode callStackState(
            String path, Map<String, Object> extra)
            throws Exception {
        return withMcpClient(
            createMcpTransport(),
            (McpClientFunction<JsonNode>) client -> {
                client.initialize();
                java.util.Map<String, Object> args =
                    new java.util.LinkedHashMap<>();
                args.put("programPath", path);
                args.put("function", "stack_state_main");
                args.putAll(extra);

                CallToolResult result =
                    client.callTool(new CallToolRequest(
                        "get-function-stack-state", args));
                assertMcpResultNotError(
                    result, "get-function-stack-state");
                return parseJsonContent(
                    ((TextContent) result.content().get(0)).text());
            });
    }

    @Test
    public void testTracksEntryRelativeStackAndFrameRegister()
            throws Exception {
        String path = createStackStateFixture();
        JsonNode json = callStackState(
            path,
            Map.of(
                "maxInstructions", 64,
                "registers", List.of("EBP")));

        assertTrue(json.get("analysisAvailable").asBoolean());
        assertEquals(
            "ESP",
            json.get("stackPointerRegister").asText());
        assertEquals(
            "ascending program address order; not execution or control-flow order",
            json.get("instructionOrder").asText());
        assertFalse(json.get("truncated").asBoolean());

        JsonNode push = findByMnemonic(json, "PUSH");
        JsonNode sub = findByMnemonic(json, "SUB");
        JsonNode movMemory =
            findByAddress(json, "0x01000406");
        JsonNode call = findByMnemonic(json, "CALL");
        JsonNode add = findByMnemonic(json, "ADD");
        JsonNode pop = findByMnemonic(json, "POP");
        JsonNode ret = findByMnemonic(json, "RET");

        assertDepth(push.get("depthBefore"), 0);
        assertEquals(-4, push.get("fallThroughDelta").asInt());

        assertDepth(sub.get("depthBefore"), -4);
        assertEquals(-32, sub.get("fallThroughDelta").asInt());

        assertDepth(movMemory.get("depthBefore"), -36);
        JsonNode ebp =
            movMemory.get("registerDepths").get(0);
        assertEquals("EBP", ebp.get("register").asText());
        assertDepth(ebp, -4);

        boolean sawResolvedStackOperand = false;
        for (JsonNode operand : movMemory.get("operands")) {
            if (operand.get("stackOffsetKnown").asBoolean()) {
                assertEquals(-8, operand.get("stackOffset").asInt());
                sawResolvedStackOperand = true;
            }
        }
        assertTrue(
            "expected [EBP-4] to resolve to entry-SP-relative stack offset -8",
            sawResolvedStackOperand);

        assertDepth(call.get("depthBefore"), -36);
        assertTrue(call.get("call").asBoolean());
        assertTrue(call.get("fallThroughDeltaKnown").asBoolean());
        assertEquals(
            "normal call fall-through should preserve net stack depth after return",
            0, call.get("fallThroughDelta").asInt());

        assertDepth(add.get("depthBefore"), -36);
        assertEquals(32, add.get("fallThroughDelta").asInt());

        assertDepth(pop.get("depthBefore"), -4);
        assertEquals(4, pop.get("fallThroughDelta").asInt());

        assertDepth(ret.get("depthBefore"), 0);
        assertFalse(ret.get("fallThroughDeltaKnown").asBoolean());
    }

    @Test
    public void testPaginationUsesCanonicalInstructionStart()
            throws Exception {
        String path = createStackStateFixture();
        JsonNode json = callStackState(
            path,
            Map.of(
                "startAddress", "0x01000407",
                "maxInstructions", 2,
                "registers", List.of("EBP")));

        assertEquals(
            "0x01000406",
            json.get("canonicalStartAddress").asText());
        assertEquals(2,
            json.get("returnedInstructionCount").asInt());
        assertTrue(json.get("truncated").asBoolean());
        assertEquals(
            "0x0100040e",
            json.get("nextStartAddress").asText());

        assertTrue(
            json.get("instructions").get(0)
                .get("instruction").asText()
                .contains("EBP"));
        assertTrue(
            json.get("instructions").get(1)
                .get("call").asBoolean());
    }

    @Test
    public void testUnknownRequestedRegisterRejected()
            throws Exception {
        String path = createStackStateFixture();

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result =
                client.callTool(new CallToolRequest(
                    "get-function-stack-state",
                    Map.of(
                        "programPath", path,
                        "function", "stack_state_main",
                        "registers",
                            List.of("NOT_A_REAL_REGISTER"))));
            assertTrue(result.isError());
            assertTrue(
                result.toString()
                    .contains("Unknown register"));
        });
    }

    private static JsonNode findByMnemonic(
            JsonNode json, String mnemonic) {
        for (JsonNode instruction : json.get("instructions")) {
            if (mnemonic.equalsIgnoreCase(
                    instruction.get("mnemonic").asText())) {
                return instruction;
            }
        }
        fail("Could not find instruction mnemonic " + mnemonic);
        return null;
    }

    private static JsonNode findByAddress(
            JsonNode json, String address) {
        for (JsonNode instruction : json.get("instructions")) {
            if (address.equals(
                    instruction.get("address").asText())) {
                return instruction;
            }
        }
        fail("Could not find instruction at " + address);
        return null;
    }

    private static void assertDepth(
            JsonNode depth, int expected) {
        assertTrue(depth.get("known").asBoolean());
        assertEquals("known", depth.get("status").asText());
        assertEquals(expected, depth.get("value").asInt());
    }
}
