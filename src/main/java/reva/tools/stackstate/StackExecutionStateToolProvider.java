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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Read-only per-instruction stack/register state derived from Ghidra's
 * CallDepthChangeInfo symbolic propagation.
 *
 * <p>The tool exposes entry-stack-pointer-relative state. It does not claim an
 * absolute runtime stack address, stack-pointer modulo alignment, or native
 * execution trace. Instruction results are returned in ascending address order,
 * not control-flow execution order.</p>
 */
public class StackExecutionStateToolProvider extends AbstractToolProvider {
    private static final int DEFAULT_MAX_INSTRUCTIONS = 128;
    private static final int HARD_MAX_INSTRUCTIONS = 1024;
    private static final int HARD_MAX_REGISTERS = 16;
    private static final int HARD_MAX_ANALYSIS_INSTRUCTIONS = 50000;

    private static final String STATE_SEMANTICS =
        "depthBefore is Ghidra CallDepthChangeInfo.getDepth() state captured before " +
        "the instruction. stackPointerDepthBefore and requested register depths are " +
        "symbolic values relative to the tracked stack-pointer value at function entry. " +
        "They are not absolute runtime addresses or stack-pointer alignment guarantees.";

    private static final String FALLTHROUGH_SEMANTICS =
        "fallThroughDelta is derived from two Ghidra pre-instruction depth states: " +
        "depthBefore(fallThrough) - depthBefore(current). It describes the statically " +
        "propagated normal fall-through edge when both states are known. It is not a " +
        "transient call push/pop trace and is not reported for non-fall-through edges.";

    private static final String OPERAND_OFFSET_SEMANTICS =
        "operand stack offsets come directly from CallDepthChangeInfo.getStackOffset() " +
        "when Ghidra can express an instruction operand through a register whose value " +
        "is tracked relative to the function-entry stack-pointer symbol. They are not " +
        "guessed from register names.";

    public StackExecutionStateToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        registerFunctionStackStateTool();
    }

    private void registerFunctionStackStateTool() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path in the Ghidra Project to the program"));
        properties.put("function",
            SchemaUtil.stringProperty("Function name, symbol, or address"));
        properties.put("startAddress",
            SchemaUtil.stringProperty(
                "Optional address or symbol inside the function. Results begin at the " +
                "containing instruction in ascending address order."));
        properties.put("maxInstructions",
            SchemaUtil.integerPropertyWithDefault(
                "Maximum instructions to return (hard cap 1024)",
                DEFAULT_MAX_INSTRUCTIONS));
        properties.put("registers",
            Map.of(
                "type", "array",
                "description",
                    "Optional register names whose values should be resolved relative to " +
                    "the function-entry stack-pointer symbol (hard cap 16).",
                "items", Map.of("type", "string"),
                "maxItems", HARD_MAX_REGISTERS));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("get-function-stack-state")
            .title("Get Function Stack Execution State")
            .description(
                "Get a bounded, read-only, per-instruction view of Ghidra " +
                "CallDepthChangeInfo state: stack depth before each instruction, " +
                "entry-relative stack-pointer/register values, fall-through depth deltas, " +
                "and operand stack offsets when Ghidra can resolve them. " +
                "Results are static analysis facts, not a native execution trace.")
            .inputSchema(createSchema(
                properties, List.of("programPath", "function")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Function function =
                getFunctionFromArgs(request.arguments(), program, "function");
            int maxInstructions = boundedPositive(
                getOptionalInt(
                    request, "maxInstructions", DEFAULT_MAX_INSTRUCTIONS),
                HARD_MAX_INSTRUCTIONS, "maxInstructions");

            List<String> requestedRegisterNames =
                getOptionalStringList(
                    request.arguments(), "registers", List.of());
            if (requestedRegisterNames.size() > HARD_MAX_REGISTERS) {
                return createErrorResult(
                    "registers exceeds hard cap " + HARD_MAX_REGISTERS);
            }

            List<Register> requestedRegisters =
                resolveRegisters(program, requestedRegisterNames);

            List<Instruction> allInstructions =
                collectInstructions(program, function);
            if (allInstructions.size() > HARD_MAX_ANALYSIS_INSTRUCTIONS) {
                return createErrorResult(
                    "Function contains " + allInstructions.size() +
                    " instructions, exceeding the analysis safety cap of " +
                    HARD_MAX_ANALYSIS_INSTRUCTIONS);
            }

            Address requestedStart = null;
            Address canonicalStart = null;
            int startIndex = 0;
            String startText =
                normalizeOptional(
                    getOptionalString(request, "startAddress", null));

            if (startText != null) {
                requestedStart =
                    AddressUtil.resolveAddressOrSymbol(program, startText);
                if (requestedStart == null) {
                    return createErrorResult(
                        "Invalid startAddress or symbol: " + startText);
                }

                Instruction containing =
                    program.getListing()
                        .getInstructionContaining(requestedStart);
                if (containing == null) {
                    return createErrorResult(
                        "No instruction contains startAddress " +
                        AddressUtil.formatAddress(requestedStart));
                }

                canonicalStart = containing.getAddress();
                if (!function.getBody().contains(canonicalStart)) {
                    return createErrorResult(
                        "startAddress " +
                        AddressUtil.formatAddress(requestedStart) +
                        " is not inside function " + function.getName());
                }

                startIndex =
                    findInstructionIndex(
                        allInstructions, canonicalStart);
                if (startIndex < 0) {
                    return createErrorResult(
                        "Canonical start instruction " +
                        AddressUtil.formatAddress(canonicalStart) +
                        " is not present in the function body");
                }
            }
            else if (!allInstructions.isEmpty()) {
                canonicalStart =
                    allInstructions.get(0).getAddress();
            }

            followRead(
                program,
                canonicalStart != null
                    ? canonicalStart : function.getEntryPoint());

            CompilerSpec compilerSpec = program.getCompilerSpec();
            Register stackPointer = compilerSpec.getStackPointer();

            CallDepthChangeInfo depthInfo = null;
            String unavailableReason = null;
            if (allInstructions.isEmpty()) {
                unavailableReason =
                    "Function body contains no instructions.";
            }
            else if (stackPointer == null) {
                unavailableReason =
                    "Ghidra compiler specification exposes no stack-pointer register.";
            }
            else {
                depthInfo =
                    new CallDepthChangeInfo(function, true);
            }

            int endExclusive =
                Math.min(
                    allInstructions.size(),
                    startIndex + maxInstructions);
            List<Map<String, Object>> states =
                new ArrayList<>(
                    Math.max(0, endExclusive - startIndex));

            for (int i = startIndex; i < endExclusive; i++) {
                states.add(
                    serializeInstructionState(
                        allInstructions.get(i),
                        function,
                        program,
                        depthInfo,
                        stackPointer,
                        requestedRegisters));
            }

            boolean truncated =
                endExclusive < allInstructions.size();

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("programPath",
                program.getDomainFile().getPathname());
            result.put("function", function.getName());
            result.put("functionAddress",
                AddressUtil.formatAddress(function.getEntryPoint()));
            result.put("analysisSource",
                "ghidra.app.cmd.function.CallDepthChangeInfo");
            result.put("analysisAvailable", depthInfo != null);
            result.put("unavailableReason", unavailableReason);
            result.put("stateSemantics", STATE_SEMANTICS);
            result.put("fallThroughSemantics", FALLTHROUGH_SEMANTICS);
            result.put("operandStackOffsetSemantics",
                OPERAND_OFFSET_SEMANTICS);
            result.put("instructionOrder",
                "ascending program address order; not execution or control-flow order");
            result.put("stackPointerRegister",
                stackPointer != null ? stackPointer.getName() : null);
            result.put("requestedRegisters",
                requestedRegisters.stream()
                    .map(Register::getName)
                    .toList());
            result.put("functionInstructionCount",
                allInstructions.size());

            result.put("requestedStartAddress",
                requestedStart != null
                    ? AddressUtil.formatAddress(requestedStart) : null);
            result.put("canonicalStartAddress",
                canonicalStart != null
                    ? AddressUtil.formatAddress(canonicalStart) : null);
            result.put("returnedInstructionCount", states.size());
            result.put("instructions", states);
            result.put("truncated", truncated);
            result.put("nextStartAddress",
                truncated
                    ? AddressUtil.formatAddress(
                        allInstructions
                            .get(endExclusive)
                            .getAddress())
                    : null);

            return createJsonResult(result);
        });
    }

    private static Map<String, Object> serializeInstructionState(
            Instruction instruction,
            Function function,
            Program program,
            CallDepthChangeInfo depthInfo,
            Register stackPointer,
            List<Register> requestedRegisters) {
        Map<String, Object> info = new LinkedHashMap<>();
        Address address = instruction.getAddress();

        info.put("address", AddressUtil.formatAddress(address));
        info.put("length", instruction.getLength());
        info.put("mnemonic", instruction.getMnemonicString());
        info.put("instruction", instruction.toString());
        info.put("flowType", instruction.getFlowType().toString());
        info.put("call", instruction.getFlowType().isCall());
        info.put("terminal", instruction.getFlowType().isTerminal());
        info.put("delaySlot", instruction.isInDelaySlot());

        int depthBefore =
            depthInfo != null
                ? depthInfo.getDepth(address)
                : Function.UNKNOWN_STACK_DEPTH_CHANGE;
        info.put("depthBefore", serializeDepth(depthBefore));

        int spDepthBefore =
            depthInfo != null && stackPointer != null
                ? depthInfo.getSPDepth(address)
                : Function.UNKNOWN_STACK_DEPTH_CHANGE;
        info.put("stackPointerDepthBefore",
            serializeDepth(spDepthBefore));

        boolean comparable =
            isKnownDepth(depthBefore) &&
            isKnownDepth(spDepthBefore);
        info.put("depthSourcesComparable", comparable);
        info.put("depthSourcesAgree",
            comparable ? depthBefore == spDepthBefore : null);

        List<Map<String, Object>> registerDepths =
            new ArrayList<>(requestedRegisters.size());
        for (Register register : requestedRegisters) {
            int value =
                depthInfo != null
                    ? depthInfo.getRegDepth(address, register)
                    : Function.UNKNOWN_STACK_DEPTH_CHANGE;
            Map<String, Object> registerInfo =
                serializeDepth(value);
            registerInfo.put("register", register.getName());
            registerInfo.put("bitLength", register.getBitLength());
            registerDepths.add(registerInfo);
        }
        info.put("registerDepths", registerDepths);

        List<Map<String, Object>> operands =
            new ArrayList<>(instruction.getNumOperands());
        for (int operandIndex = 0;
                operandIndex < instruction.getNumOperands();
                operandIndex++) {
            Map<String, Object> operand =
                new LinkedHashMap<>();
            operand.put("index", operandIndex);
            operand.put("text",
                instruction
                    .getDefaultOperandRepresentation(
                        operandIndex));

            int stackOffset =
                depthInfo != null
                    ? depthInfo.getStackOffset(
                        instruction, operandIndex)
                    : Function.INVALID_STACK_DEPTH_CHANGE;
            Map<String, Object> offsetState =
                serializeDepth(stackOffset);
            operand.put("stackOffsetKnown",
                offsetState.get("known"));
            operand.put("stackOffsetStatus",
                offsetState.get("status"));
            operand.put("stackOffset",
                offsetState.get("value"));
            operands.add(operand);
        }
        info.put("operands", operands);

        Address fallThrough = instruction.getFallThrough();
        boolean sameFunctionFallThrough =
            fallThrough != null &&
            function.getBody().contains(fallThrough);

        info.put("fallThroughAddress",
            fallThrough != null
                ? AddressUtil.formatAddress(fallThrough)
                : null);
        info.put("fallThroughInsideFunction",
            sameFunctionFallThrough);

        int fallThroughDepth =
            sameFunctionFallThrough && depthInfo != null
                ? depthInfo.getDepth(fallThrough)
                : Function.UNKNOWN_STACK_DEPTH_CHANGE;
        info.put("fallThroughDepthBefore",
            serializeDepth(fallThroughDepth));

        if (isKnownDepth(depthBefore) &&
            isKnownDepth(fallThroughDepth)) {
            info.put("fallThroughDeltaKnown", true);
            info.put("fallThroughDelta",
                fallThroughDepth - depthBefore);
        }
        else {
            info.put("fallThroughDeltaKnown", false);
            info.put("fallThroughDelta", null);
        }

        return info;
    }

    private static Map<String, Object> serializeDepth(int value) {
        Map<String, Object> result = new LinkedHashMap<>();
        if (value == Function.UNKNOWN_STACK_DEPTH_CHANGE) {
            result.put("known", false);
            result.put("status", "unknown");
            result.put("value", null);
        }
        else if (value == Function.INVALID_STACK_DEPTH_CHANGE) {
            result.put("known", false);
            result.put("status", "invalid");
            result.put("value", null);
        }
        else {
            result.put("known", true);
            result.put("status", "known");
            result.put("value", value);
        }
        return result;
    }

    private static boolean isKnownDepth(int value) {
        return value != Function.UNKNOWN_STACK_DEPTH_CHANGE &&
            value != Function.INVALID_STACK_DEPTH_CHANGE;
    }

    private static List<Instruction> collectInstructions(
            Program program, Function function) {
        List<Instruction> instructions = new ArrayList<>();
        InstructionIterator iterator =
            program.getListing()
                .getInstructions(function.getBody(), true);
        while (iterator.hasNext()) {
            instructions.add(iterator.next());
        }
        return instructions;
    }

    private static int findInstructionIndex(
            List<Instruction> instructions, Address address) {
        for (int i = 0; i < instructions.size(); i++) {
            if (instructions.get(i).getAddress().equals(address)) {
                return i;
            }
        }
        return -1;
    }

    private static List<Register> resolveRegisters(
            Program program, List<String> names) {
        Set<String> seen = new LinkedHashSet<>();
        List<Register> registers = new ArrayList<>();

        for (String rawName : names) {
            String name =
                rawName != null ? rawName.trim() : "";
            if (name.isEmpty()) {
                throw new IllegalArgumentException(
                    "registers must not contain blank names");
            }

            Register register = program.getRegister(name);
            if (register == null) {
                throw new IllegalArgumentException(
                    "Unknown register: " + name);
            }

            if (seen.add(register.getName())) {
                registers.add(register);
            }
        }

        return registers;
    }

    private static String normalizeOptional(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value;
    }

    private static int boundedPositive(
            int value, int hardMax, String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(
                name + " must be greater than zero");
        }
        return Math.min(value, hardMax);
    }
}
