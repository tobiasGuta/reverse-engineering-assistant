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
package reva.tools.stackabi;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Read-only access to Ghidra's stack-frame and calling-convention models.
 *
 * <p>The tools deliberately preserve Ghidra's stack-space coordinate system.
 * Stack offsets returned here are not silently reinterpreted as literal
 * RBP/RSP displacement operands or as ABI stack-alignment guarantees.</p>
 */
public class StackAbiToolProvider extends AbstractToolProvider {
    private static final int DEFAULT_MAX_VARIABLES = 256;
    private static final int DEFAULT_MAX_PARAMETERS = 128;
    private static final int HARD_MAX_VARIABLES = 1024;
    private static final int HARD_MAX_PARAMETERS = 512;
    private static final int HARD_MAX_STORAGE_ITEMS = 256;
    private static final int HARD_MAX_VARNODES_PER_STORAGE = 32;

    private static final String STACK_OFFSET_SEMANTICS =
        "Stack offsets are Ghidra stack-space offsets. They are not necessarily " +
        "frame-pointer-relative machine addresses and must not be interpreted as literal " +
        "RBP/RSP displacement operands.";

    public StackAbiToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerFunctionStackFrameTool();
        registerFunctionAbiTool();
    }

    private void registerFunctionStackFrameTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("function",
            SchemaUtil.stringProperty("Function name, symbol, or address"));
        properties.put("maxVariables", SchemaUtil.integerPropertyWithDefault(
            "Maximum defined stack variables to return (hard cap 1024)",
            DEFAULT_MAX_VARIABLES));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-function-stack-frame")
            .title("Get Function Stack Frame")
            .description("Get a bounded, read-only view of Ghidra's StackFrame model for a function: " +
                "frame/local/parameter sizes, parameter and return-address offsets, stack direction, " +
                "defined stack variables, exact VariableStorage, and byte deltas within the same " +
                "Ghidra stack-space coordinate system. Does not infer literal RBP/RSP displacements.")
            .inputSchema(createSchema(properties, List.of("programPath", "function")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Function function = getFunctionFromArgs(request.arguments(), program, "function");
            int maxVariables = boundedPositive(
                getOptionalInt(request, "maxVariables", DEFAULT_MAX_VARIABLES),
                HARD_MAX_VARIABLES, "maxVariables");

            followRead(program, function.getEntryPoint());

            CompilerSpec compilerSpec = program.getCompilerSpec();
            StackFrame frame = function.getStackFrame();

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("function", function.getName());
            result.put("functionAddress", AddressUtil.formatAddress(function.getEntryPoint()));
            result.put("offsetSemantics", STACK_OFFSET_SEMANTICS);

            Map<String, Object> stackModel = new LinkedHashMap<>();
            putRegisterName(stackModel, "stackPointerRegister", compilerSpec.getStackPointer());
            if (compilerSpec.getStackSpace() != null) {
                stackModel.put("stackSpace", compilerSpec.getStackSpace().getName());
            }
            if (compilerSpec.getStackBaseSpace() != null) {
                stackModel.put("stackBaseSpace", compilerSpec.getStackBaseSpace().getName());
            }
            stackModel.put("compilerStackGrowsNegative", compilerSpec.stackGrowsNegative());
            stackModel.put("stackRightJustified", compilerSpec.isStackRightJustified());
            result.put("stackModel", stackModel);

            Map<String, Object> frameInfo = new LinkedHashMap<>();
            frameInfo.put("frameSize", frame.getFrameSize());
            frameInfo.put("localSize", frame.getLocalSize());
            frameInfo.put("parameterSize", frame.getParameterSize());
            int parameterOffset = frame.getParameterOffset();
            boolean parameterOffsetKnown = parameterOffset != StackFrame.UNKNOWN_PARAM_OFFSET;
            frameInfo.put("parameterOffsetKnown", parameterOffsetKnown);
            if (parameterOffsetKnown) {
                frameInfo.put("parameterOffset", parameterOffset);
            }
            frameInfo.put("returnAddressOffset", frame.getReturnAddressOffset());
            frameInfo.put("growsNegative", frame.growsNegative());
            frameInfo.put("offsetCoordinateSystem", "ghidra-stack-space");
            frameInfo.put("provenance", "Function.getStackFrame()");
            result.put("frame", frameInfo);

            Variable[] variables = frame.getStackVariables();
            int returnedCount = Math.min(maxVariables, variables.length);
            List<Map<String, Object>> variableData = new ArrayList<>(returnedCount);
            for (int i = 0; i < returnedCount; i++) {
                Variable variable = variables[i];
                Map<String, Object> info = serializeVariable(variable, program);
                VariableStorage storage = variable.getVariableStorage();
                if (storage != null && storage.hasStackStorage()) {
                    int stackOffset = storage.getStackOffset();
                    info.put("stackOffset", stackOffset);
                    info.put("byteDeltaFromStackOffsetToReturnAddress",
                        (long) frame.getReturnAddressOffset() - stackOffset);
                }
                variableData.add(info);
            }

            result.put("variableCount", variables.length);
            result.put("returnedVariableCount", variableData.size());
            result.put("variables", variableData);
            result.put("truncated", variables.length > variableData.size());

            return createJsonResult(result);
        });
    }

    private void registerFunctionAbiTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("function",
            SchemaUtil.stringProperty("Function name, symbol, or address"));
        properties.put("maxParameters", SchemaUtil.integerPropertyWithDefault(
            "Maximum parameters to return (hard cap 512)", DEFAULT_MAX_PARAMETERS));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-function-abi")
            .title("Get Function ABI")
            .description("Get a bounded, read-only view of Ghidra's function signature, parameter/return " +
                "storage, compiler stack model, and PrototypeModel calling-convention facts. " +
                "Reports stackParameterAlignment using Ghidra's exact meaning (alignment of individual " +
                "stack parameters); it does not claim a call-site or function-entry RSP alignment.")
            .inputSchema(createSchema(properties, List.of("programPath", "function")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Function function = getFunctionFromArgs(request.arguments(), program, "function");
            int maxParameters = boundedPositive(
                getOptionalInt(request, "maxParameters", DEFAULT_MAX_PARAMETERS),
                HARD_MAX_PARAMETERS, "maxParameters");

            followRead(program, function.getEntryPoint());

            CompilerSpec compilerSpec = program.getCompilerSpec();
            PrototypeModel model = function.getCallingConvention();

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programPath", program.getDomainFile().getPathname());
            result.put("function", function.getName());
            result.put("functionAddress", AddressUtil.formatAddress(function.getEntryPoint()));
            result.put("stackOffsetSemantics", STACK_OFFSET_SEMANTICS);

            Map<String, Object> signature = new LinkedHashMap<>();
            signature.put("effectivePrototype", function.getPrototypeString(false, true));
            signature.put("formalPrototype", function.getPrototypeString(true, true));
            signature.put("signatureSource", function.getSignatureSource().toString());
            signature.put("callingConventionName", function.getCallingConventionName());
            signature.put("callingConventionUnknown", function.hasUnknownCallingConventionName());
            signature.put("hasCustomVariableStorage", function.hasCustomVariableStorage());
            signature.put("varArgs", function.hasVarArgs());
            signature.put("noReturn", function.hasNoReturn());
            boolean stackPurgeSizeKnown = function.isStackPurgeSizeValid();
            signature.put("stackPurgeSizeKnown", stackPurgeSizeKnown);
            if (stackPurgeSizeKnown) {
                signature.put("stackPurgeSize", function.getStackPurgeSize());
            }
            else {
                signature.put("stackPurgeSize", null);
            }
            result.put("signature", signature);

            Map<String, Object> compilerModel = new LinkedHashMap<>();
            compilerModel.put("compilerSpec",
                compilerSpec.getCompilerSpecID().getIdAsString());
            putRegisterName(compilerModel, "stackPointerRegister", compilerSpec.getStackPointer());
            if (compilerSpec.getStackSpace() != null) {
                compilerModel.put("stackSpace", compilerSpec.getStackSpace().getName());
            }
            if (compilerSpec.getStackBaseSpace() != null) {
                compilerModel.put("stackBaseSpace", compilerSpec.getStackBaseSpace().getName());
            }
            compilerModel.put("stackGrowsNegative", compilerSpec.stackGrowsNegative());
            compilerModel.put("stackRightJustified", compilerSpec.isStackRightJustified());
            result.put("compilerModel", compilerModel);

            Map<String, Object> convention = new LinkedHashMap<>();
            convention.put("resolved", model != null);
            convention.put("stackParameterAlignmentSemantics",
                "Alignment required for individual parameters allocated on the stack; " +
                "not a function-entry or call-site stack-pointer alignment guarantee.");

            String conventionUnavailableReason = null;
            if (model != null) {
                convention.put("unavailableReason", null);
                convention.put("name", model.getName());
                convention.put("mergedModel", model.isMerged());
                convention.put("programExtension", model.isProgramExtension());
                convention.put("hasThisPointer", model.hasThisPointer());
                convention.put("constructor", model.isConstructor());
                convention.put("hasInjection", model.hasInjection());

                Long stackParameterOffset = model.getStackParameterOffset();
                convention.put("stackParameterOffset", stackParameterOffset);
                convention.put("stackParameterAlignment", model.getStackParameterAlignment());
                convention.put("stackShift", model.getStackshift());

                int extraPop = model.getExtrapop();
                boolean extraPopKnown = extraPop != PrototypeModel.UNKNOWN_EXTRAPOP;
                convention.put("extraPopKnown", extraPopKnown);
                if (extraPopKnown) {
                    convention.put("extraPop", extraPop);
                }
                else {
                    convention.put("extraPop", null);
                }

                putBoundedVarnodes(convention, "returnAddressStorage",
                    model.getReturnAddress(), program);
                putBoundedStorages(convention, "potentialInputRegisterStorage",
                    model.getPotentialInputRegisterStorage(program), program);
                putBoundedVarnodes(convention, "unaffectedStorage",
                    model.getUnaffectedList(), program);
                putBoundedVarnodes(convention, "killedByCallStorage",
                    model.getKilledByCallList(), program);
                putBoundedVarnodes(convention, "likelyTrashStorage",
                    model.getLikelyTrash(), program);
            }
            else {
                conventionUnavailableReason =
                    "Ghidra has no resolved PrototypeModel for this function's calling convention.";
                convention.put("unavailableReason", conventionUnavailableReason);
                convention.put("name", null);
                convention.put("mergedModel", null);
                convention.put("programExtension", null);
                convention.put("hasThisPointer", null);
                convention.put("constructor", null);
                convention.put("hasInjection", null);
                convention.put("stackParameterOffset", null);
                convention.put("stackParameterAlignment", null);
                convention.put("stackShift", null);
                convention.put("extraPopKnown", false);
                convention.put("extraPop", null);
                putUnavailableBoundedItems(convention, "returnAddressStorage");
                putUnavailableBoundedItems(convention, "potentialInputRegisterStorage");
                putUnavailableBoundedItems(convention, "unaffectedStorage");
                putUnavailableBoundedItems(convention, "killedByCallStorage");
                putUnavailableBoundedItems(convention, "likelyTrashStorage");
            }

            result.put("callingConvention", convention);
            result.put("callingConventionUnavailable", conventionUnavailableReason);

            Parameter returnValue = function.getReturn();
            result.put("returnValue", serializeParameter(returnValue, program));

            Parameter[] parameters = function.getParameters();
            int returnedCount = Math.min(maxParameters, parameters.length);
            List<Map<String, Object>> parameterData = new ArrayList<>(returnedCount);
            for (int i = 0; i < returnedCount; i++) {
                parameterData.add(serializeParameter(parameters[i], program));
            }
            result.put("parameterCount", parameters.length);
            result.put("returnedParameterCount", parameterData.size());
            result.put("parameters", parameterData);
            result.put("parametersTruncated", parameters.length > parameterData.size());

            return createJsonResult(result);
        });
    }

    private static Map<String, Object> serializeVariable(Variable variable, Program program) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("name", variable.getName());
        info.put("kind", variable instanceof Parameter ? "parameter" : "local");
        info.put("dataType", variable.getDataType().getDisplayName());
        info.put("length", variable.getLength());
        info.put("source", variable.getSource().toString());
        info.put("firstUseOffset", variable.getFirstUseOffset());
        info.put("valid", variable.isValid());
        info.put("storage", serializeStorage(variable.getVariableStorage(), program));
        return info;
    }

    private static Map<String, Object> serializeParameter(Parameter parameter, Program program) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("ordinal", parameter.getOrdinal());
        info.put("name", parameter.getName());
        info.put("effectiveDataType", parameter.getDataType().getDisplayName());
        info.put("formalDataType", parameter.getFormalDataType().getDisplayName());
        info.put("source", parameter.getSource().toString());
        info.put("autoParameter", parameter.isAutoParameter());
        if (parameter.getAutoParameterType() != null) {
            info.put("autoParameterType", parameter.getAutoParameterType().toString());
        }
        info.put("forcedIndirect", parameter.isForcedIndirect());
        info.put("storage", serializeStorage(parameter.getVariableStorage(), program));
        return info;
    }

    private static Map<String, Object> serializeStorage(
            VariableStorage storage, Program program) {
        Map<String, Object> info = new LinkedHashMap<>();
        if (storage == null) {
            info.put("kind", "none");
            info.put("valid", false);
            info.put("varnodes", List.of());
            return info;
        }

        info.put("kind", storageKind(storage));
        info.put("valid", storage.isValid());
        info.put("autoStorage", storage.isAutoStorage());
        info.put("forcedIndirect", storage.isForcedIndirect());
        info.put("varnodeCount", storage.getVarnodeCount());

        if (storage.hasStackStorage()) {
            info.put("stackOffset", storage.getStackOffset());
        }

        List<Register> registers = storage.getRegisters();
        if (registers != null && !registers.isEmpty()) {
            List<String> registerNames = new ArrayList<>(registers.size());
            for (Register register : registers) {
                registerNames.add(register.getName());
            }
            info.put("registers", registerNames);
        }
        else {
            info.put("registers", List.of());
        }

        Varnode[] varnodes = storage.getVarnodes();
        int count = varnodes == null ? 0 : varnodes.length;
        int returned = Math.min(count, HARD_MAX_VARNODES_PER_STORAGE);
        List<Map<String, Object>> nodes = new ArrayList<>(returned);
        for (int i = 0; i < returned; i++) {
            nodes.add(serializeVarnode(varnodes[i], program));
        }
        info.put("varnodes", nodes);
        info.put("varnodesTruncated", count > returned);
        return info;
    }

    private static String storageKind(VariableStorage storage) {
        if (storage.isBadStorage()) {
            return "bad";
        }
        if (storage.isUnassignedStorage()) {
            return "unassigned";
        }
        if (storage.isVoidStorage()) {
            return "void";
        }
        if (storage.isCompoundStorage()) {
            return "compound";
        }
        if (storage.isStackStorage()) {
            return "stack";
        }
        if (storage.isRegisterStorage()) {
            return "register";
        }
        if (storage.isMemoryStorage()) {
            return "memory";
        }
        if (storage.isConstantStorage()) {
            return "constant";
        }
        if (storage.isHashStorage()) {
            return "hash";
        }
        if (storage.isUniqueStorage()) {
            return "unique";
        }
        return "other";
    }

    private static Map<String, Object> serializeVarnode(Varnode node, Program program) {
        Map<String, Object> info = new LinkedHashMap<>();
        info.put("repr", node.toString(program.getLanguage()));
        info.put("size", node.getSize());

        Address address = node.getAddress();
        if (address != null) {
            info.put("address", address.toString());
            info.put("space", address.getAddressSpace().getName());
            info.put("offset", address.getOffset());
        }

        Register register = program.getRegister(node);
        if (register != null) {
            info.put("register", register.getName());
        }

        info.put("constant", node.isConstant());
        info.put("unique", node.isUnique());
        info.put("addressTied", node.isAddrTied());
        return info;
    }

    private static void putBoundedVarnodes(Map<String, Object> target, String key,
            Varnode[] varnodes, Program program) {
        int count = varnodes == null ? 0 : varnodes.length;
        int returned = Math.min(count, HARD_MAX_STORAGE_ITEMS);
        List<Map<String, Object>> items = new ArrayList<>(returned);
        for (int i = 0; i < returned; i++) {
            items.add(serializeVarnode(varnodes[i], program));
        }
        target.put(key, items);
        target.put(key + "Count", count);
        target.put(key + "Truncated", count > returned);
    }

    private static void putBoundedStorages(Map<String, Object> target, String key,
            VariableStorage[] storages, Program program) {
        int count = storages == null ? 0 : storages.length;
        int returned = Math.min(count, HARD_MAX_STORAGE_ITEMS);
        List<Map<String, Object>> items = new ArrayList<>(returned);
        for (int i = 0; i < returned; i++) {
            items.add(serializeStorage(storages[i], program));
        }
        target.put(key, items);
        target.put(key + "Count", count);
        target.put(key + "Truncated", count > returned);
    }

    private static void putUnavailableBoundedItems(
            Map<String, Object> target, String key) {
        target.put(key, List.of());
        target.put(key + "Count", 0);
        target.put(key + "Truncated", false);
    }

    private static void putRegisterName(
            Map<String, Object> target, String key, Register register) {
        if (register != null) {
            target.put(key, register.getName());
        }
    }

    private static int boundedPositive(int value, int hardMax, String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(name + " must be greater than zero");
        }
        return Math.min(value, hardMax);
    }
}
