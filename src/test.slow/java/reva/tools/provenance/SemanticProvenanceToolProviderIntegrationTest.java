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

import io.modelcontextprotocol.spec.McpSchema.CallToolRequest;
import io.modelcontextprotocol.spec.McpSchema.CallToolResult;
import io.modelcontextprotocol.spec.McpSchema.TextContent;
import reva.AnalyzedFixtureSupport;
import reva.RevaIntegrationTestBase;

/**
 * Exercises the semantic-provenance tools against the existing analyzed
 * data-flow fixture. Its main function calls transform(11), giving the test a
 * stable direct call, one concrete argument, decompiler markup, High P-code,
 * and machine-address provenance in one small real binary.
 */
public class SemanticProvenanceToolProviderIntegrationTest
        extends RevaIntegrationTestBase {

    private static final String FIXTURE = "test_dataflow_x86_64";

    private record FunctionRef(String name, String address) {}

    private FunctionRef resolveFunction(
            String path, String baseName) throws Exception {
        return withMcpClient(
            createMcpTransport(),
            (McpClientFunction<FunctionRef>) client -> {
                client.initialize();
                CallToolResult result =
                    client.callTool(new CallToolRequest(
                        "get-symbols",
                        Map.of(
                            "programPath", path,
                            "maxCount", 500,
                            "filterDefaultNames", true)));
                assertMcpResultNotError(
                    result, "get-symbols for " + baseName);

                JsonNode json = parseJsonContent(
                    ((TextContent) result.content().get(0)).text());

                for (JsonNode symbol : json.get("symbols")) {
                    if (!symbol.path("isFunction").asBoolean(false)) {
                        continue;
                    }
                    String name = symbol.path("name").asText();
                    if (baseName.equals(name) ||
                        ("_" + baseName).equals(name)) {
                        return new FunctionRef(
                            name, symbol.get("address").asText());
                    }
                }

                fail("Could not find function " + baseName +
                    " or _" + baseName);
                return null;
            });
    }

    private JsonNode findCallToken(
            String path, String functionName) throws Exception {
        return withMcpClient(
            createMcpTransport(),
            (McpClientFunction<JsonNode>) client -> {
                client.initialize();
                CallToolResult result =
                    client.callTool(new CallToolRequest(
                        "get-decompiler-provenance",
                        Map.of(
                            "programPath", path,
                            "function", functionName,
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
        String path =
            AnalyzedFixtureSupport.importAndAnalyze(this, FIXTURE);
        FunctionRef main = resolveFunction(path, "main");

        JsonNode token = findCallToken(path, main.name());

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
        String path =
            AnalyzedFixtureSupport.importAndAnalyze(this, FIXTURE);
        FunctionRef main = resolveFunction(path, "main");
        JsonNode callToken = findCallToken(path, main.name());
        int displayLine =
            callToken.get("displayLineNumber").asInt();

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result =
                client.callTool(new CallToolRequest(
                    "get-decompiler-provenance",
                    Map.of(
                        "programPath", path,
                        "function", main.name(),
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
    public void testCallsiteSemanticsReportsTargetAndConcreteArgument()
            throws Exception {
        String path =
            AnalyzedFixtureSupport.importAndAnalyze(this, FIXTURE);
        FunctionRef main = resolveFunction(path, "main");
        JsonNode callToken = findCallToken(path, main.name());
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
            assertEquals(main.name(), json.get("caller").asText());
            assertTrue(json.get("callOperationCount").asInt() > 0);

            JsonNode call = json.get("calls").get(0);
            assertEquals("CALL", call.get("opcode").asText());
            assertTrue(call.get("direct").asBoolean());
            assertTrue(call.get("target").get("resolved").asBoolean());
            assertTrue(
                call.get("target").get("name").asText()
                    .contains("transform"));
            assertTrue(
                call.get("statementText").asText()
                    .contains("transform"));
            assertTrue(call.get("argumentCount").asInt() >= 1);
            assertFalse(call.get("argumentsTruncated").asBoolean());

            boolean sawEleven = false;
            for (JsonNode argument : call.get("arguments")) {
                JsonNode varnode = argument.get("varnode");
                if (varnode.path("constant").asBoolean(false) &&
                    "0xb".equals(varnode.path("value").asText())) {
                    sawEleven = true;
                    break;
                }
            }
            assertTrue(
                "transform(11) should expose a High P-code constant argument 0xb",
                sawEleven);

            assertTrue(
                json.get("argumentSemantics").asText()
                    .contains("not reconstructed source expressions"));
        });
    }

    @Test
    public void testDecompilerProvenanceRequiresSelector()
            throws Exception {
        String path =
            AnalyzedFixtureSupport.importAndAnalyze(this, FIXTURE);
        FunctionRef main = resolveFunction(path, "main");

        withMcpClient(createMcpTransport(), client -> {
            client.initialize();
            CallToolResult result =
                client.callTool(new CallToolRequest(
                    "get-decompiler-provenance",
                    Map.of(
                        "programPath", path,
                        "function", main.name())));
            assertTrue(
                "selector-less provenance request should be rejected",
                result.isError());
            assertTrue(
                result.toString().contains(
                    "At least one selector is required"));
        });
    }
}
