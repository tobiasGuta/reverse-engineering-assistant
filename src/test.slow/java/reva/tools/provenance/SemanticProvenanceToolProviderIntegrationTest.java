/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.tools.provenance;

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
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.RevaIntegrationTestBase;

/**
 * Exercises the semantic-provenance tools against a self-contained synthetic
 * x86-64 program. The fixture deliberately avoids Git LFS dependencies while
 * still providing a real direct call, one concrete argument, decompiler markup,
 * High P-code, SSA varnodes, and machine-address provenance.
 */
public class SemanticProvenanceToolProviderIntegrationTest
        extends RevaIntegrationTestBase {

    private static final long MAIN_ADDRESS = 0x01000300L;
    private static final long TRANSFORM_ADDRESS = 0x01000320L;

    private String createSemanticFixture() throws Exception {
        Address mainStart =
            program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(MAIN_ADDRESS);
        Address transformStart =
            program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(TRANSFORM_ADDRESS);

        // main(int seed):
        //   push rbp
        //   mov  rbp,rsp
        //   call transform      // seed remains in EDI
        //   pop  rbp
        //   ret
        byte[] mainBytes = {
            (byte) 0x55,
            (byte) 0x48, (byte) 0x89, (byte) 0xe5,
            (byte) 0xe8, (byte) 0x17, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x5d,
            (byte) 0xc3
        };

        // transform(int seed):
        //   push rbp
        //   mov  rbp,rsp
        //   mov  eax,edi
        //   add  eax,7
        //   pop  rbp
        //   ret
        byte[] transformBytes = {
            (byte) 0x55,
            (byte) 0x48, (byte) 0x89, (byte) 0xe5,
            (byte) 0x89, (byte) 0xf8,
            (byte) 0x83, (byte) 0xc0, (byte) 0x07,
            (byte) 0x5d,
            (byte) 0xc3
        };

        Address mainEnd = mainStart.add(mainBytes.length - 1L);
        Address transformEnd =
            transformStart.add(transformBytes.length - 1L);

        int tx = program.startTransaction(
            "create semantic provenance fixture");
        try {
            program.getMemory().setBytes(mainStart, mainBytes);
            program.getMemory().setBytes(
                transformStart, transformBytes);

            DisassembleCommand mainDisassemble =
                new DisassembleCommand(mainStart, null, true);
            DisassembleCommand transformDisassemble =
                new DisassembleCommand(transformStart, null, true);

            assertTrue("synthetic main should disassemble",
                mainDisassemble.applyTo(
                    program, TaskMonitor.DUMMY));
            assertTrue("synthetic transform should disassemble",
                transformDisassemble.applyTo(
                    program, TaskMonitor.DUMMY));

            FunctionManager manager =
                program.getFunctionManager();

            Function transform = manager.createFunction(
                "transform",
                transformStart,
                new AddressSet(transformStart, transformEnd),
                SourceType.USER_DEFINED);
            assertNotNull(
                "synthetic transform should be created", transform);

            Function main = manager.createFunction(
                "main",
                mainStart,
                new AddressSet(mainStart, mainEnd),
                SourceType.USER_DEFINED);
            assertNotNull(
                "synthetic main should be created", main);

            PrototypeModel defaultConvention =
                program.getCompilerSpec()
                    .getDefaultCallingConvention();
            assertNotNull(
                "compiler spec should define a default calling convention",
                defaultConvention);
            transform.setCallingConvention(
                defaultConvention.getName());
            main.setCallingConvention(
                defaultConvention.getName());

            transform.setReturnType(
                DWordDataType.dataType,
                SourceType.USER_DEFINED);
            transform.addParameter(
                new ParameterImpl(
                    "seed",
                    DWordDataType.dataType,
                    program,
                    SourceType.USER_DEFINED),
                SourceType.USER_DEFINED);

            main.setReturnType(
                DWordDataType.dataType,
                SourceType.USER_DEFINED);
            main.addParameter(
                new ParameterImpl(
                    "seed",
                    DWordDataType.dataType,
                    program,
                    SourceType.USER_DEFINED),
                SourceType.USER_DEFINED);
        }
        finally {
            program.endTransaction(tx, true);
        }

        env.open(program);
        ProgramManager programManager =
            tool.getService(ProgramManager.class);
        assertNotNull(
            "ProgramManager service", programManager);
        programManager.openProgram(program);
        serverManager.programOpened(program, tool);

        return program.getDomainFile().getPathname();
    }

    private int findDecompilationLineContaining(
            String path, String needle) throws Exception {
        return withMcpClient(
            createMcpTransport(),
            (McpClientFunction<Integer>) client -> {
                client.initialize();
                CallToolResult result =
                    client.callTool(new CallToolRequest(
                        "get-decompilation",
                        Map.of(
                            "programPath", path,
                            "functionNameOrAddress", "main")));
                assertMcpResultNotError(
                    result, "get-decompilation");

                JsonNode json = parseJsonContent(
                    ((TextContent) result.content().get(0)).text());
                String decompilation =
                    json.get("decompilation").asText();

                for (String line : decompilation.split("\\n")) {
                    int tab = line.indexOf('\t');
                    if (tab <= 0) {
                        continue;
                    }
                    String body = line.substring(tab + 1);
                    if (body.contains(needle)) {
                        return Integer.parseInt(
                            line.substring(0, tab).trim());
                    }
                }

                fail("Could not find decompilation line containing " + needle);
                return -1;
            });
    }

    private JsonNode findCallToken(String path) throws Exception {
        return withMcpClient(
            createMcpTransport(),
            (McpClientFunction<JsonNode>) client -> {
                client.initialize();
                CallToolResult result =
                    client.callTool(new CallToolRequest(
                        "get-decompiler-provenance",
                        Map.of(
                            "programPath", path,
                            "function", "main",
                            "tokenText", "transform",
                            "maxTokens", 32)));
                assertMcpResultNotError(
                    result, "get-decompiler-provenance");

                JsonNode json = parseJsonContent(
                    ((TextContent) result.content().get(0)).text());
                assertTrue(
                    "provenance search should match a transform token",
                    json.get("matchedTokenCount").asInt() > 0);

                for (JsonNode token : json.get("tokens")) {
                    if ("ClangFuncNameToken".equals(
                            token.path("tokenClass").asText()) &&
                        "CALL".equals(
                            token.path("pcodeOp")
                                .path("mnemonic").asText())) {
                        return token;
                    }
                }

                fail("Could not find a decompiler function-name token " +
                    "linked to the transform CALL");
                return null;
            });
    }

    @Test
    public void testDecompilerProvenanceLinksCallTokenToHighPcode()
            throws Exception {
        String path = createSemanticFixture();
        JsonNode token = findCallToken(path);

        assertTrue(token.get("directAddressLinked").asBoolean());
        assertTrue(token.get("minAddress").asText().startsWith("0x"));
        assertEquals(
            token.get("minAddress").asText(),
            token.get("pcodeOp")
                .get("sequenceAddress").asText());
        assertTrue(
            token.get("lineText").asText().contains("transform"));
        assertTrue(
            token.hasNonNull("displayLineNumber"));
    }

    @Test
    public void testDisplayLineSelectorKeepsDecompilerContext()
            throws Exception {
        String path = createSemanticFixture();
        JsonNode callToken = findCallToken(path);
        int displayLine =
            callToken.get("displayLineNumber").asInt();
        int decompilationLine =
            findDecompilationLineContaining(path, "transform");

        assertEquals(
            "provenance display line must match get-decompilation numbering",
            decompilationLine, displayLine);

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result =
                client.callTool(new CallToolRequest(
                    "get-decompiler-provenance",
                    Map.of(
                        "programPath", path,
                        "function", "main",
                        "displayLine", displayLine,
                        "maxTokens", 64)));
            assertMcpResultNotError(
                result, "get-decompiler-provenance line selector");

            JsonNode json = parseJsonContent(
                ((TextContent) result.content().get(0)).text());
            assertTrue(json.get("matchedTokenCount").asInt() > 0);

            boolean sawTransformCall = false;
            for (JsonNode token : json.get("tokens")) {
                assertEquals(
                    displayLine,
                    token.get("displayLineNumber").asInt());
                if (token.path("text").asText().contains("transform") &&
                    "CALL".equals(
                        token.path("pcodeOp")
                            .path("mnemonic").asText())) {
                    sawTransformCall = true;
                }
            }

            assertTrue(
                "selected decompiler line should retain the transform call token",
                sawTransformCall);
        });
    }

    @Test
    public void testCallsiteSemanticsReportsTargetAndArgumentProvenance()
            throws Exception {
        String path = createSemanticFixture();
        JsonNode callToken = findCallToken(path);
        String callsite = callToken.get("minAddress").asText();

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result =
                client.callTool(new CallToolRequest(
                    "get-callsite-semantics",
                    Map.of(
                        "programPath", path,
                        "callsite", callsite,
                        "maxArguments", 16)));
            assertMcpResultNotError(
                result, "get-callsite-semantics");

            JsonNode json = parseJsonContent(
                ((TextContent) result.content().get(0)).text());
            assertEquals(callsite, json.get("callsite").asText());
            assertEquals("main", json.get("caller").asText());
            assertTrue(json.get("callOperationCount").asInt() > 0);

            JsonNode call = json.get("calls").get(0);
            assertEquals("CALL", call.get("opcode").asText());
            assertTrue(call.get("direct").asBoolean());
            assertTrue(call.get("target").get("resolved").asBoolean());
            assertEquals(
                "transform",
                call.get("target").get("name").asText());
            assertTrue(
                call.get("statementText").asText()
                    .contains("transform"));
            assertTrue(
                "call-site statement should retain display-line context",
                call.get("statementLines").isArray() &&
                call.get("statementLines").size() > 0);
            assertEquals(
                findDecompilationLineContaining(path, "transform"),
                call.get("statementLines").get(0).asInt());
            assertTrue(call.get("argumentCount").asInt() >= 1);
            assertFalse(call.get("argumentsTruncated").asBoolean());

            JsonNode argument = call.get("arguments").get(0);
            assertEquals(0, argument.get("index").asInt());

            JsonNode varnode = argument.get("varnode");
            assertNotNull("first call argument should expose a Varnode", varnode);
            assertTrue(varnode.hasNonNull("repr"));
            assertTrue(varnode.get("size").asInt() > 0);
            assertTrue(varnode.hasNonNull("kind"));

            assertTrue(argument.has("producer"));
            JsonNode producer = argument.get("producer");
            if (producer != null && !producer.isNull()) {
                assertTrue(producer.hasNonNull("mnemonic"));
                assertTrue(producer.get("inputs").isArray());
            }

            assertTrue(argument.get("relatedDecompilerTokens").isArray());
            assertTrue(argument.has("relatedDecompilerTokenCount"));
            assertTrue(argument.has("relatedDecompilerTokensTruncated"));
            assertTrue(
                "direct parameter argument should expose at least one related token",
                argument.get("relatedDecompilerTokenCount").asInt() > 0);

            for (JsonNode related :
                    argument.get("relatedDecompilerTokens")) {
                assertTrue(
                    "related token should keep its Clang line number",
                    related.hasNonNull("clangLineNumber"));
                assertTrue(
                    "related token should keep get-decompilation display line",
                    related.hasNonNull("displayLineNumber"));
                assertTrue(
                    "related token should keep contextual line text",
                    related.hasNonNull("lineText"));
                assertTrue(
                    "related token should keep its line token index",
                    related.get("lineTokenIndex").asInt() >= 0);
            }

            assertTrue(
                json.get("argumentSemantics").asText()
                    .contains("not reconstructed source expressions"));
            assertTrue(
                json.get("argumentSemantics").asText()
                    .contains("immediate defining High P-code operation"));
        });
    }

    @Test
    public void testDecompilerProvenanceRequiresSelector()
            throws Exception {
        String path = createSemanticFixture();

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result =
                client.callTool(new CallToolRequest(
                    "get-decompiler-provenance",
                    Map.of(
                        "programPath", path,
                        "function", "main")));
            assertTrue(
                "selector-less provenance request should be rejected",
                result.isError());
            assertTrue(
                result.toString().contains(
                    "At least one selector is required"));
        });
    }

}
