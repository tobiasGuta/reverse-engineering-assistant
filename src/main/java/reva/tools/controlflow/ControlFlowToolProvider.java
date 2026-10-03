/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reva.tools.controlflow;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.CyclomaticComplexity;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Read-only intraprocedural control-flow tools.
 */
public class ControlFlowToolProvider extends AbstractToolProvider {
    private static final int DEFAULT_MAX_BLOCKS = 256;
    private static final int HARD_MAX_BLOCKS = 1024;
    private static final int HARD_MAX_EDGES_PER_BLOCK = 64;
    private static final int MAX_BLOCK_SCAN = 4096;

    public ControlFlowToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerFunctionCfgTool();
    }

    private void registerFunctionCfgTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("function",
            SchemaUtil.stringProperty("Function name, symbol, or address"));
        properties.put("maxBlocks", SchemaUtil.integerPropertyWithDefault(
            "Maximum basic blocks to return (hard cap 1024)", DEFAULT_MAX_BLOCKS));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-function-cfg")
            .title("Get Function Control Flow")
            .description("Get a bounded, read-only basic-block control-flow graph for a function, " +
                "including block ranges, branch edges, flow types, internal/external destinations, " +
                "and cyclomatic complexity. Use when decompilation is incomplete, optimized, or " +
                "when exact branch structure matters.")
            .inputSchema(createSchema(properties, List.of("programPath", "function")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Function function = getFunctionFromArgs(request.arguments(), program, "function");
            int maxBlocks = getOptionalInt(request, "maxBlocks", DEFAULT_MAX_BLOCKS);
            if (maxBlocks <= 0) {
                return createErrorResult("maxBlocks must be greater than zero");
            }
            maxBlocks = Math.min(maxBlocks, HARD_MAX_BLOCKS);

            followRead(program, function.getEntryPoint());

            try {
                BasicBlockModel model = new BasicBlockModel(program);
                CodeBlockIterator iterator = model.getCodeBlocksContaining(
                    function.getBody(), TaskMonitor.DUMMY);

                List<CodeBlock> allBlocks = new ArrayList<>();
                boolean scanTruncated = false;
                while (iterator.hasNext()) {
                    CodeBlock block = iterator.next();
                    Address start = block.getFirstStartAddress();
                    if (start == null || !function.getBody().contains(start)) {
                        continue;
                    }
                    if (allBlocks.size() >= MAX_BLOCK_SCAN) {
                        scanTruncated = true;
                        break;
                    }
                    allBlocks.add(block);
                }
                allBlocks.sort(Comparator.comparing(CodeBlock::getFirstStartAddress));

                int returnCount = Math.min(maxBlocks, allBlocks.size());
                List<Map<String, Object>> blocks = new ArrayList<>(returnCount);
                int returnedEdgeCount = 0;
                boolean edgesTruncated = false;

                for (int i = 0; i < returnCount; i++) {
                    CodeBlock block = allBlocks.get(i);
                    Map<String, Object> blockInfo = new LinkedHashMap<>();
                    blockInfo.put("start", AddressUtil.formatAddress(block.getFirstStartAddress()));
                    blockInfo.put("minAddress", AddressUtil.formatAddress(block.getMinAddress()));
                    blockInfo.put("maxAddress", AddressUtil.formatAddress(block.getMaxAddress()));
                    blockInfo.put("size", block.getNumAddresses());
                    blockInfo.put("flowType", block.getFlowType().toString());

                    List<Map<String, Object>> destinations = new ArrayList<>();
                    CodeBlockReferenceIterator refs = block.getDestinations(TaskMonitor.DUMMY);
                    int blockEdgeCount = 0;
                    while (refs.hasNext()) {
                        CodeBlockReference ref = refs.next();
                        blockEdgeCount++;
                        if (destinations.size() >= HARD_MAX_EDGES_PER_BLOCK) {
                            edgesTruncated = true;
                            continue;
                        }

                        Map<String, Object> edge = new LinkedHashMap<>();
                        Address destination = ref.getDestinationAddress();
                        Address referent = ref.getReferent();
                        if (destination != null) {
                            edge.put("to", AddressUtil.formatAddress(destination));
                            edge.put("internal", function.getBody().contains(destination));
                        }
                        if (referent != null) {
                            edge.put("fromInstruction", AddressUtil.formatAddress(referent));
                        }
                        edge.put("flowType", ref.getFlowType().toString());
                        destinations.add(edge);
                    }
                    returnedEdgeCount += destinations.size();
                    blockInfo.put("destinationCount", blockEdgeCount);
                    blockInfo.put("destinations", destinations);
                    blockInfo.put("destinationsTruncated", blockEdgeCount > destinations.size());
                    blocks.add(blockInfo);
                }

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("programPath", program.getDomainFile().getPathname());
                result.put("function", function.getName());
                result.put("functionAddress", AddressUtil.formatAddress(function.getEntryPoint()));
                result.put("functionSize", function.getBody().getNumAddresses());
                result.put("blockCount", allBlocks.size());
                result.put("returnedBlockCount", blocks.size());
                result.put("blocks", blocks);
                result.put("returnedEdgeCount", returnedEdgeCount);
                result.put("truncated", scanTruncated || allBlocks.size() > blocks.size() || edgesTruncated);
                if (scanTruncated) {
                    result.put("note", "Basic-block scan stopped at the safety cap of " + MAX_BLOCK_SCAN +
                        " blocks; counts may be incomplete.");
                }

                try {
                    int complexity = new CyclomaticComplexity()
                        .calculateCyclomaticComplexity(function, TaskMonitor.DUMMY);
                    result.put("cyclomaticComplexity", complexity);
                } catch (CancelledException e) {
                    result.put("cyclomaticComplexityUnavailable", "calculation cancelled");
                }

                return createJsonResult(result);
            }
            catch (CancelledException e) {
                return createErrorResult("Control-flow analysis was cancelled");
            }
        });
    }
}
