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
package reva.tools.pcode;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Read-only access to Ghidra's architecture-neutral raw P-code.
 *
 * <p>The provider is intentionally bounded and does not execute P-code. It is a
 * semantic fallback for cases where decompilation is incomplete or exact machine
 * semantics matter.</p>
 */
public class PcodeToolProvider extends AbstractToolProvider {
    private static final int DEFAULT_MAX_INSTRUCTIONS = 64;
    private static final int DEFAULT_MAX_OPS = 512;
    private static final int HARD_MAX_INSTRUCTIONS = 256;
    private static final int HARD_MAX_OPS = 4096;

    public PcodeToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerGetPcodeTool();
    }

    private void registerGetPcodeTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("target",
            SchemaUtil.stringProperty("Address, symbol, or function name to inspect"));
        properties.put("scope", Map.of(
            "type", "string",
            "description", "P-code scope: instruction, basic-block, or function",
            "enum", List.of("instruction", "basic-block", "function"),
            "default", "instruction"));
        properties.put("maxInstructions", SchemaUtil.integerPropertyWithDefault(
            "Maximum instructions to inspect (hard cap 256)", DEFAULT_MAX_INSTRUCTIONS));
        properties.put("maxOps", SchemaUtil.integerPropertyWithDefault(
            "Maximum P-code operations to return (hard cap 4096)", DEFAULT_MAX_OPS));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-pcode")
            .title("Get P-code")
            .description("Get bounded raw Ghidra P-code for an instruction, basic block, or function. " +
                "Returns architecture-neutral operation semantics and varnodes without executing the program. " +
                "Use as a fallback when decompilation is ambiguous, optimized, or unavailable.")
            .inputSchema(createSchema(properties, List.of("programPath", "target")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            String scope = getOptionalString(request, "scope", "instruction");
            if (!List.of("instruction", "basic-block", "function").contains(scope)) {
                return createErrorResult("scope must be one of: instruction, basic-block, function");
            }

            int maxInstructions = boundedPositive(
                getOptionalInt(request, "maxInstructions", DEFAULT_MAX_INSTRUCTIONS),
                HARD_MAX_INSTRUCTIONS, "maxInstructions");
            int maxOps = boundedPositive(
                getOptionalInt(request, "maxOps", DEFAULT_MAX_OPS),
                HARD_MAX_OPS, "maxOps");

            Listing listing = program.getListing();
            Address targetAddress;
            InstructionIterator instructions;
            String resolvedFunction = null;
            String scopeStart = null;
            String scopeEnd = null;

            try {
                if ("function".equals(scope)) {
                    Function function = getFunctionFromArgs(request.arguments(), program, "target");
                    targetAddress = function.getEntryPoint();
                    instructions = listing.getInstructions(function.getBody(), true);
                    resolvedFunction = function.getName();
                    scopeStart = AddressUtil.formatAddress(function.getBody().getMinAddress());
                    scopeEnd = AddressUtil.formatAddress(function.getBody().getMaxAddress());
                }
                else {
                    targetAddress = getAddressFromArgs(request, program, "target");
                    if ("instruction".equals(scope)) {
                        Instruction instruction = listing.getInstructionContaining(targetAddress);
                        if (instruction == null) {
                            return createErrorResult("No instruction contains " +
                                AddressUtil.formatAddress(targetAddress));
                        }
                        instructions = listing.getInstructions(instruction.getAddress(), true);
                        maxInstructions = 1;
                        scopeStart = AddressUtil.formatAddress(instruction.getAddress());
                        scopeEnd = AddressUtil.formatAddress(instruction.getMaxAddress());
                    }
                    else {
                        BasicBlockModel model = new BasicBlockModel(program);
                        CodeBlock block = model.getFirstCodeBlockContaining(targetAddress, TaskMonitor.DUMMY);
                        if (block == null) {
                            return createErrorResult("No basic block contains " +
                                AddressUtil.formatAddress(targetAddress));
                        }
                        instructions = listing.getInstructions(block, true);
                        scopeStart = AddressUtil.formatAddress(block.getMinAddress());
                        scopeEnd = AddressUtil.formatAddress(block.getMaxAddress());
                    }
                }
            }
            catch (CancelledException e) {
                return createErrorResult("P-code scope resolution was cancelled");
            }

            followRead(program, targetAddress);

            List<Map<String, Object>> instructionData = new ArrayList<>();
            int operationCount = 0;
            int visitedInstructions = 0;
            boolean truncated = false;

            while (instructions.hasNext()) {
                if (visitedInstructions >= maxInstructions || operationCount >= maxOps) {
                    truncated = true;
                    break;
                }

                Instruction instruction = instructions.next();
                visitedInstructions++;
                PcodeOp[] ops = instruction.getPcode();

                Map<String, Object> instructionInfo = new LinkedHashMap<>();
                instructionInfo.put("address", AddressUtil.formatAddress(instruction.getAddress()));
                instructionInfo.put("assembly", instruction.toString());
                instructionInfo.put("flowType", instruction.getFlowType().toString());

                List<Map<String, Object>> pcode = new ArrayList<>();
                for (PcodeOp op : ops) {
                    if (operationCount >= maxOps) {
                        truncated = true;
                        break;
                    }
                    pcode.add(formatPcodeOp(op, program));
                    operationCount++;
                }
                instructionInfo.put("pcode", pcode);
                instructionInfo.put("pcodeCount", pcode.size());
                instructionData.add(instructionInfo);

                if (operationCount >= maxOps) {
                    truncated = true;
                    break;
                }
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("scope", scope);
            result.put("target", getString(request, "target"));
            result.put("resolvedAddress", AddressUtil.formatAddress(targetAddress));
            if (resolvedFunction != null) {
                result.put("function", resolvedFunction);
            }
            if (scopeStart != null) {
                result.put("scopeStart", scopeStart);
            }
            if (scopeEnd != null) {
                result.put("scopeEnd", scopeEnd);
            }
            result.put("instructionCount", instructionData.size());
            result.put("operationCount", operationCount);
            result.put("instructions", instructionData);
            result.put("truncated", truncated);
            if (truncated) {
                result.put("note", "Output stopped at the requested safety bounds; narrow the scope or paginate by target.");
            }
            return createJsonResult(result);
        });
    }

    private static Map<String, Object> formatPcodeOp(PcodeOp op, Program program) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("mnemonic", op.getMnemonic());
        if (op.getSeqnum() != null && op.getSeqnum().getTarget() != null) {
            info.put("sequenceAddress", AddressUtil.formatAddress(op.getSeqnum().getTarget()));
        }
        info.put("sequenceOrder", op.getSeqnum() != null ? op.getSeqnum().getOrder() : 0);

        Varnode output = op.getOutput();
        if (output != null) {
            info.put("output", formatVarnode(output, program));
        }

        List<Map<String, Object>> inputs = new ArrayList<>();
        for (int i = 0; i < op.getNumInputs(); i++) {
            Varnode input = op.getInput(i);
            if (input != null) {
                inputs.add(formatVarnode(input, program));
            }
        }
        info.put("inputs", inputs);
        return info;
    }

    private static Map<String, Object> formatVarnode(Varnode node, Program program) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("repr", node.toString(program.getLanguage()));
        info.put("size", node.getSize());
        Address address = node.getAddress();
        if (address != null) {
            info.put("address", address.toString());
            info.put("space", address.getAddressSpace().getName());
        }
        info.put("constant", node.isConstant());
        info.put("register", node.isRegister());
        info.put("unique", node.isUnique());
        info.put("addressTied", node.isAddrTied());
        if (node.isConstant()) {
            info.put("value", "0x" + Long.toUnsignedString(node.getOffset(), 16));
        }
        return info;
    }

    private static int boundedPositive(int value, int hardMax, String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(name + " must be greater than zero");
        }
        return Math.min(value, hardMax);
    }
}
