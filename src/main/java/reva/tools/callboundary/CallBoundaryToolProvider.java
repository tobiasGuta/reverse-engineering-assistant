/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 */
package reva.tools.callboundary;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.util.task.TimeoutTaskMonitor;
import io.modelcontextprotocol.server.McpSyncServer;
import io.modelcontextprotocol.spec.McpSchema;
import reva.tools.AbstractToolProvider;
import reva.util.AddressUtil;
import reva.util.SchemaUtil;

/**
 * Read-only, single-call-boundary evidence. This does not run a target or
 * perform interprocedural propagation. Ghidra's decompiler models are not
 * runtime observations, and a positional correspondence is not a proof of
 * the machine ABI or of actual value equality.
 */
public final class CallBoundaryToolProvider extends AbstractToolProvider {
    private static final int DECOMPILE_TIMEOUT_SECONDS = 30;
    private static final int DEFAULT_MAX_ARGUMENTS = 32;
    private static final int HARD_MAX_ARGUMENTS = 128;
    private static final int MAX_CALL_OPS = 8;
    private static final int MAX_RETURN_SITES = 16;
    private static final int MAX_RETURN_SCAN_OPS = 50_000;

    public CallBoundaryToolProvider(McpSyncServer server) {
        super(server);
    }

    @Override
    public void registerTools() {
        Map<String, Object> properties = new LinkedHashMap<>();
        properties.put("programPath",
            SchemaUtil.stringProperty("Path in the Ghidra project"));
        properties.put("callsite",
            SchemaUtil.stringProperty("Machine call instruction address or symbol"));
        properties.put("maxArguments", SchemaUtil.integerPropertyWithDefault(
            "Maximum High P-code arguments per call (hard cap 128)",
            DEFAULT_MAX_ARGUMENTS));

        McpSchema.Tool tool = McpSchema.Tool.builder()
            .name("inspect-call-boundary")
            .title("Inspect Call Boundary Evidence")
            .description("Read-only, bounded evidence for a machine call: caller and " +
                "decompiler CALL/CALLIND operations, argument varnodes, exact direct " +
                "targets when available, callee prototype and returned-value models. " +
                "Mappings are decompiler-derived candidates, never runtime-verified.")
            .inputSchema(createSchema(properties, List.of("programPath", "callsite")))
            .build();

        registerTool(tool, (exchange, request) -> {
            Program program = getProgramFromArgs(request);
            Address requested = getAddressFromArgs(request, program, "callsite");
            Instruction instruction =
                program.getListing().getInstructionContaining(requested);
            if (instruction == null) {
                return createErrorResult("No instruction contains " +
                    AddressUtil.formatAddress(requested));
            }
            Address callsite = instruction.getAddress();
            if (!instruction.getFlowType().isCall()) {
                return createErrorResult("Instruction is not a machine call: " +
                    AddressUtil.formatAddress(callsite));
            }
            Function caller =
                program.getFunctionManager().getFunctionContaining(callsite);
            if (caller == null) {
                return createErrorResult("No function contains call site " +
                    AddressUtil.formatAddress(callsite));
            }
            int maxArguments =
                getOptionalInt(request, "maxArguments", DEFAULT_MAX_ARGUMENTS);
            if (maxArguments <= 0 || maxArguments > HARD_MAX_ARGUMENTS) {
                return createErrorResult("maxArguments must be between 1 and " +
                    HARD_MAX_ARGUMENTS);
            }

            followRead(program, callsite);
            DecompInterface decompiler = new DecompInterface();
            decompiler.toggleCCode(false);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");
            if (!decompiler.openProgram(program)) {
                decompiler.dispose();
                return createErrorResult("Could not initialize Ghidra decompiler");
            }
            try {
                HighFunction callerHigh = decompile(decompiler, caller);
                if (callerHigh == null) {
                    return createErrorResult("Caller decompilation unavailable: " +
                        caller.getName());
                }

                List<PcodeOpAST> calls = new ArrayList<>();
                int callOpCount = 0;
                var atAddress = callerHigh.getPcodeOps(callsite);
                while (atAddress.hasNext()) {
                    PcodeOpAST op = atAddress.next();
                    if (op.getOpcode() == PcodeOp.CALL ||
                        op.getOpcode() == PcodeOp.CALLIND) {
                        callOpCount++;
                        if (calls.size() < MAX_CALL_OPS) {
                            calls.add(op);
                        }
                    }
                }
                if (callOpCount == 0) {
                    return createErrorResult("Machine call has no recovered " +
                        "High P-code CALL/CALLIND operation at " +
                        AddressUtil.formatAddress(callsite));
                }

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("programPath", program.getDomainFile().getPathname());
                result.put("requestedAddress", AddressUtil.formatAddress(requested));
                result.put("callsite", AddressUtil.formatAddress(callsite));
                result.put("machineInstruction", instruction.toString());
                result.put("caller", functionIdentity(caller));
                result.put("callOperationCount", callOpCount);
                result.put("returnedCallOperationCount", calls.size());
                result.put("callOperationsTruncated", callOpCount > calls.size());
                result.put("semantics",
                    "High P-code and function signatures are decompiler/static " +
                    "models. Positional correspondences are candidates, not " +
                    "runtime observations, proven ABI registers, or whole-program " +
                    "dataflow. No target execution or Ghidra database changes.");

                List<Map<String, Object>> observations = new ArrayList<>();
                for (PcodeOpAST op : calls) {
                    observations.add(observeCall(program, decompiler, op,
                        maxArguments));
                }
                result.put("calls", observations);
                return createJsonResult(result);
            }
            finally {
                decompiler.dispose();
            }
        });
    }

    private Map<String, Object> observeCall(Program program,
            DecompInterface decompiler, PcodeOpAST call, int maxArguments) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("opcode", call.getMnemonic());
        result.put("sequence", call.getSeqnum().toString());

        int numArguments = Math.max(0, call.getNumInputs() - 1);
        int returnedArguments = Math.min(numArguments, maxArguments);
        result.put("argumentCount", numArguments);
        result.put("returnedArgumentCount", returnedArguments);
        result.put("argumentsTruncated", numArguments > returnedArguments);
        List<Map<String, Object>> arguments = new ArrayList<>();
        for (int i = 0; i < returnedArguments; i++) {
            Map<String, Object> argument = new LinkedHashMap<>();
            argument.put("index", i);
            argument.put("value", varnode(call.getInput(i + 1)));
            arguments.add(argument);
        }
        result.put("arguments", arguments);
        result.put("callerReturnValue", varnode(call.getOutput()));

        Varnode target = call.getNumInputs() > 0 ? call.getInput(0) : null;
        if (call.getOpcode() == PcodeOp.CALLIND) {
            result.put("targetKind", "indirect_unresolved");
            result.put("targetVarnode", varnode(target));
            result.put("mappingStatus", "unavailable_indirect_target");
            result.put("callee", null);
            return result;
        }

        if (target == null || target.getAddress() == null) {
            result.put("targetKind", "direct_unresolved");
            result.put("targetVarnode", varnode(target));
            result.put("mappingStatus", "unavailable_target");
            result.put("callee", null);
            return result;
        }

        Address targetAddress = target.getAddress();
        result.put("targetAddress", AddressUtil.formatAddress(targetAddress));
        Function callee =
            program.getFunctionManager().getFunctionAt(targetAddress);
        if (callee == null) {
            result.put("targetKind", "direct_no_function");
            result.put("callee", null);
            result.put("mappingStatus", "unavailable_target_function");
            return result;
        }

        result.put("targetKind",
            callee.isExternal() ? "external" :
            callee.isThunk() ? "thunk" : "direct_internal");
        result.put("callee", functionIdentity(callee));
        if (callee.isExternal() || callee.isThunk()) {
            result.put("mappingStatus", "unavailable_external_or_thunk");
            return result;
        }

        HighFunction calleeHigh = decompile(decompiler, callee);
        if (calleeHigh == null) {
            result.put("mappingStatus", "unavailable_callee_decompilation");
            return result;
        }

        Parameter[] formals = callee.getParameters();
        int decompilerParamCount =
            calleeHigh.getFunctionPrototype().getNumParams();
        result.put("formalParameterCount", formals.length);
        result.put("decompilerParameterCount", decompilerParamCount);
        result.put("variadic", callee.hasVarArgs());
        result.put("customStorage", callee.hasCustomVariableStorage());
        result.put("callingConventionUnknown",
            callee.hasUnknownCallingConventionName());

        boolean hasSpecialStorage = formals.length > maxArguments;
        List<Map<String, Object>> formalInfo = new ArrayList<>();
        for (int i = 0; i < Math.min(formals.length, maxArguments); i++) {
            Parameter formal = formals[i];
            Map<String, Object> info = new LinkedHashMap<>();
            info.put("index", i);
            info.put("name", formal.getName());
            info.put("type", formal.getDataType().getDisplayName());
            info.put("storage", formal.getVariableStorage().toString());
            info.put("autoParameter", formal.isAutoParameter());
            info.put("forcedIndirect", formal.isForcedIndirect());
            hasSpecialStorage |= formal.isAutoParameter() ||
                formal.isForcedIndirect();
            formalInfo.add(info);
        }
        result.put("formalParameters", formalInfo);
        result.put("formalsTruncated", formals.length > formalInfo.size());

        boolean eligible = !callee.hasVarArgs() &&
            !callee.hasCustomVariableStorage() &&
            !callee.hasUnknownCallingConventionName() &&
            !hasSpecialStorage &&
            numArguments == formals.length &&
            decompilerParamCount == formals.length &&
            !Boolean.TRUE.equals(result.get("argumentsTruncated")) &&
            !Boolean.TRUE.equals(result.get("formalsTruncated"));
        result.put("mappingStatus", eligible ?
            "decompiler_positional_candidate" : "ambiguous_prototype_or_storage");
        if (eligible) {
            for (int i = 0; i < arguments.size(); i++) {
                arguments.get(i).put("candidateFormalIndex", i);
                arguments.get(i).put("candidateFormalName", formals[i].getName());
            }
        }

        int returnCount = 0;
        int scannedOps = 0;
        boolean returnScanTruncated = false;
        List<Map<String, Object>> returnEvidence = new ArrayList<>();
        var ops = calleeHigh.getPcodeOps();
        while (ops.hasNext()) {
            if (scannedOps >= MAX_RETURN_SCAN_OPS) {
                returnScanTruncated = true;
                break;
            }
            scannedOps++;
            PcodeOpAST op = ops.next();
            if (op.getOpcode() != PcodeOp.RETURN) {
                continue;
            }
            returnCount++;
            if (returnEvidence.size() < MAX_RETURN_SITES) {
                Map<String, Object> site = new LinkedHashMap<>();
                site.put("address", AddressUtil.formatAddress(
                    op.getSeqnum().getTarget()));
                site.put("value", op.getNumInputs() > 1 ?
                    varnode(op.getInput(1)) : null);
                returnEvidence.add(site);
            }
        }
        result.put("calleeReturnSiteCount", returnCount);
        result.put("returnScanTruncated", returnScanTruncated);
        result.put("returnSiteCountExact", !returnScanTruncated);
        result.put("calleeReturnSites", returnEvidence);
        result.put("returnSitesTruncated",
            returnScanTruncated || returnCount > returnEvidence.size());
        result.put("returnRelationship",
            call.getOutput() == null ? "no_caller_output_model" :
            returnCount == 0 ? "callee_return_unavailable" :
            "separate_caller_and_callee_models_not_runtime_equivalence");
        return result;
    }

    private HighFunction decompile(DecompInterface d, Function function) {
        DecompileResults result = d.decompileFunction(
            function, DECOMPILE_TIMEOUT_SECONDS,
            TimeoutTaskMonitor.timeoutIn(
                DECOMPILE_TIMEOUT_SECONDS, TimeUnit.SECONDS));
        return result != null && result.decompileCompleted()
            ? result.getHighFunction() : null;
    }

    private static Map<String, Object> functionIdentity(Function f) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", f.getName());
        out.put("address", AddressUtil.formatAddress(f.getEntryPoint()));
        out.put("external", f.isExternal());
        out.put("thunk", f.isThunk());
        return out;
    }

    private static Map<String, Object> varnode(Varnode v) {
        if (v == null) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("address", AddressUtil.formatAddress(v.getAddress()));
        out.put("sizeBytes", v.getSize());
        out.put("constant", v.isConstant());
        out.put("register", v.isRegister());
        out.put("unique", v.isUnique());
        out.put("addressSpaceValue", v.isAddress());
        if (v.isConstant()) {
            out.put("constantUnsignedHex", Long.toUnsignedString(
                v.getOffset(), 16));
        }
        return out;
    }
}
